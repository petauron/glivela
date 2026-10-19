//go:build linux

package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

// Native-core integration: the exact rendered entry config and
// official clients are real. The small PROXY-v1 frontend is a test fixture,
// not a replacement for installed ingress/Docker/UID/firewall acceptance.
// All services and apparently public IPs exist only in this unrouted netns.
func TestRenderedEntryAccountAuthentication(t *testing.T) {
	if os.Getenv("GLIVELA_ENTRY_AUTH_TEST") != "1" {
		t.Skip("isolated Linux authentication fixture required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	initial, initialErr := os.Readlink("/proc/1/ns/net")
	mountNamespace, mountErr := os.Readlink("/proc/self/ns/mnt")
	initialMount, initialMountErr := os.Readlink("/proc/1/ns/mnt")
	if err != nil || initialErr != nil || current == initial || os.Geteuid() != 0 || mountErr != nil || initialMountErr != nil || mountNamespace == initialMount {
		t.Fatal("refusing authentication test outside isolated root network/mount namespaces")
	}
	// Sniffing intentionally restores example.com from the payload's SNI.
	// Poison system resolution with a private answer. Only Glivela's explicit
	// business resolver may resolve the unchanged sniffed SNI to the target.
	// This bind mount is private to the newly created mount namespace only.
	hosts := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(hosts, "/etc/hosts", "", syscall.MS_BIND, ""); err != nil {
		t.Fatal("private fixture hosts mount failed", err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount("/etc/hosts", 0); err != nil {
			t.Error("private fixture hosts unmount failed", err)
		}
	})
	driver := officialTestDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ip := func(args ...string) {
		t.Helper()
		if err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).Run(); err != nil {
			t.Fatal("isolated interface setup failed", err)
		}
	}
	ip("link", "set", "lo", "up")
	for _, address := range []string{"100.64.0.3/32", "100.64.0.4/32", "93.184.216.34/32", "1.1.1.1/32", "1.0.0.1/32"} {
		ip("addr", "add", address, "dev", "lo")
	}
	dnsLog := filepath.Join(t.TempDir(), "resolver.log")
	stopDNS := startEntryResolverFixture(t, ctx, "93.184.216.34", dnsLog)
	defer stopDNS()
	decoy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	decoy.Listener.Close()
	decoy.Listener, err = net.Listen("tcp", "100.64.0.4:0")
	if err != nil {
		t.Fatal(err)
	}
	decoy.EnableHTTP2 = true
	decoy.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	decoy.StartTLS()
	defer decoy.Close()
	var requests atomic.Int64
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != "example.com" {
			w.WriteHeader(400)
			return
		}
		requests.Add(1)
		w.WriteHeader(204)
	}))
	target.Listener.Close()
	target.Listener, err = net.Listen("tcp", "93.184.216.34:0")
	if err != nil {
		t.Fatal(err)
	}
	target.StartTLS()
	defer target.Close()
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())
	if err := target.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatal("target certificate fixture has wrong identity")
	}
	s, d, _, _ := subscriptionFixture(t, false, decoy.Listener.Addr().String())
	front := startEntryProxyFixture(t, ctx, "100.64.0.3:14443", net.JoinHostPort(d.Entry.RealityEndpoints[0].ListenAddress, fmt.Sprint(d.Entry.RealityEndpoints[0].ListenPort)))
	first, second := d.Entry.Credentials[0], d.Entry.Credentials[1]
	primary := startRealityClientFixture(t, ctx, driver, d.Entry.RealityEndpoints[0], front, first.ProtocolID)
	other := startRealityClientFixture(t, ctx, driver, d.Entry.RealityEndpoints[0], front, second.ProtocolID)
	unknown := startRealityClientFixture(t, ctx, driver, d.Entry.RealityEndpoints[0], front, "33333333-3333-4333-8333-333333333333")
	directory := t.TempDir()
	start := func(desired Desired) func() {
		t.Helper()
		path := filepath.Join(directory, fmt.Sprintf("entry-%d.json", desired.Revision))
		if err := os.WriteFile(path, desired.Config, 0600); err != nil {
			t.Fatal(err)
		}
		return startAuthenticationCore(t, ctx, driver, path, net.JoinHostPort(desired.Entry.RealityEndpoints[0].ListenAddress, fmt.Sprint(desired.Entry.RealityEndpoints[0].ListenPort)))
	}
	probe := func(address string, want bool) {
		t.Helper()
		before := requests.Load()
		timeout := 3 * time.Second
		if want {
			// Pinned REALITY waits in five-second intervals for its asynchronous
			// target-record detector after TCP listen is ready. A two-second TLS
			// deadline races this startup, not credential or DNS validation.
			timeout = 8 * time.Second
		}
		err := probeAuthenticatedEntryWithin(ctx, address, target.URL, pool, timeout)
		if want {
			if err != nil || requests.Load() != before+1 {
				t.Fatal("valid original credential could not reach verified TLS target", err)
			}
		} else if err == nil || requests.Load() != before {
			t.Fatal("disabled/unknown credential reached target")
		}
	}
	stop := start(d)
	probe(primary, true)
	probe(other, true)
	probe(unknown, false)
	stop()
	primaryPlan := s.business.material.Plan.Accounts[0].Account.Plan
	disabled := primaryPlan
	disabled.Enabled = false
	if _, err := s.UpdateAccountPlan(ctx, "account-example", 7, disabled); err != nil {
		t.Fatal(err)
	}
	currentDesired := func() Desired {
		for _, node := range s.nodes {
			if node.ID == "entry-example" {
				return node.Desired
			}
		}
		t.Fatal("entry identity missing")
		return Desired{}
	}
	stop = start(currentDesired())
	probe(primary, false)
	probe(other, true)
	stop()
	otherPlan := s.business.material.Plan.Accounts[1].Account.Plan
	otherDisabled := otherPlan
	otherDisabled.Enabled = false
	if _, err := s.UpdateAccountPlan(ctx, "account-other", 1, otherDisabled); err != nil {
		t.Fatal(err)
	}
	stop = start(currentDesired())
	probe(primary, false)
	probe(other, false)
	probe(unknown, false)
	stop()
	if _, err := s.UpdateAccountPlan(ctx, "account-example", 8, primaryPlan); err != nil {
		t.Fatal(err)
	}
	reenabled := currentDesired()
	if reenabled.Entry.Credentials[0].ProtocolID != first.ProtocolID || reenabled.Entry.Credentials[1].ProtocolID != second.ProtocolID {
		t.Fatal("account toggles regenerated protocol identity")
	}
	stop = start(reenabled)
	probe(primary, true)
	probe(other, false)
	stop()
	if _, err := s.UpdateAccountPlan(ctx, "account-other", 2, otherPlan); err != nil {
		t.Fatal(err)
	}
	stop = start(currentDesired())
	defer stop()
	probe(primary, true)
	probe(other, true)
	stop()
	t.Run("hysteria2", func(t *testing.T) {
		exerciseHysteriaAccountAuthentication(t, ctx, driver, decoy, target, pool, &requests)
	})
	t.Run("native-DNS-and-target-safety", func(t *testing.T) {
		exerciseEntryNativeTargetSafety(t, ctx, driver, currentDesired(), front, target, pool, &requests, stopDNS)
	})
	log, err := os.ReadFile(dnsLog)
	if err != nil || !strings.Contains(string(log), "query[A] example.com") {
		t.Fatal("business resolver query was not observed", err)
	}
}

func startEntryResolverFixture(t *testing.T, ctx context.Context, answer, logPath string) func() {
	t.Helper()
	command := exec.CommandContext(ctx, "dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--no-resolv", "--no-hosts", "--local-ttl=1", "--bind-interfaces", "--listen-address=1.1.1.1,1.0.0.1", "--user=root", "--pid-file="+filepath.Join(t.TempDir(), "dns.pid"), "--log-queries", "--log-facility="+logPath, "--host-record=example.com,"+answer)
	if err := command.Start(); err != nil {
		t.Fatal("isolated resolver did not start", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait(); close(done) }()
	var once sync.Once
	stop := func() { once.Do(func() { _ = command.Process.Kill(); <-done }) }
	t.Cleanup(stop)
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case <-done:
			t.Fatal("isolated resolver exited")
		default:
		}
		connection, err := net.DialTimeout("tcp", "1.1.1.1:53", 100*time.Millisecond)
		if err == nil {
			connection.Close()
			return stop
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated resolver unavailable")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Fixed PROXY protocol fixture required by the unchanged rendered entry
// transport. It forwards only to this test's one exact backend, no open proxy.
func startEntryProxyFixture(t *testing.T, ctx context.Context, address, backend string) string {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(12 * time.Second))
				server, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", backend)
				if err != nil {
					return
				}
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(12 * time.Second))
				if _, err := io.WriteString(server, "PROXY TCP4 100.64.0.3 100.64.0.3 12345 10443\r\n"); err != nil {
					return
				}
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(server, client); _ = server.Close(); close(copied) }()
				_, _ = io.Copy(client, server)
				_ = client.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; workers.Wait() })
	return listener.Addr().String()
}

func startRealityClientFixture(t *testing.T, ctx context.Context, driver SystemdDriver, endpoint glivela.RealityEndpoint, front, protocolID string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, port := listener.Addr().String(), listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	host, frontPort, err := net.SplitHostPort(front)
	if err != nil {
		t.Fatal(err)
	}
	var number int
	if _, err := fmt.Sscan(frontPort, &number); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": number, "users": []any{map[string]any{"id": protocolID, "encryption": "none", "flow": "xtls-rprx-vision"}}}}}, "streamSettings": map[string]any{"method": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": endpoint.ServerNames[0], "fingerprint": "chrome", "password": endpoint.PublicKey, "shortId": endpoint.ShortIDs[0]}}}}}
	// Keep bounded anonymous client diagnostics on failure as well as server
	// diagnostics, so a rejected REALITY handshake is not mistaken for DNS.
	config["log"] = map[string]any{"loglevel": "info"}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	stop := startAuthenticationCore(t, ctx, driver, path, address)
	t.Cleanup(stop)
	return address
}

func startAuthenticationCore(t *testing.T, parent context.Context, driver SystemdDriver, path, address string) func() {
	t.Helper()
	if err := validateXrayFile(parent, driver.Binary, driver.BinarySHA256, path); err != nil {
		t.Fatal("authentication fixture config rejected", err)
	}
	ctx, cancel := context.WithCancel(parent)
	command := exec.CommandContext(ctx, driver.Binary, "run", "-config", path)
	var diagnostics entryDockerOutput
	command.Stdout, command.Stderr = &diagnostics, &diagnostics
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal("official core did not start", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
		})
	}
	t.Cleanup(stop)
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			raw := diagnostics.String()
			if len(raw) > 8192 {
				raw = raw[len(raw)-8192:]
			}
			t.Log("anonymous authentication fixture diagnostics:", raw)
		}
	})
	deadline := time.Now().Add(4 * time.Second)
	for {
		select {
		case <-done:
			t.Fatal("official core exited before listener acceptance", diagnostics.String())
		default:
		}
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("official authentication listener unavailable")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return stop
}

func probeAuthenticatedEntry(ctx context.Context, address, target string, roots *x509.CertPool) error {
	return probeAuthenticatedEntryWithin(ctx, address, target, roots, 3*time.Second)
}

func probeAuthenticatedEntryWithin(ctx context.Context, address, target string, roots *x509.CertPool, timeout time.Duration) error {
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: address}), TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, ResponseHeaderTimeout: 2 * time.Second, TLSHandshakeTimeout: timeout - time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("authenticated request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 204 {
		return fmt.Errorf("unexpected target status")
	}
	return nil
}
