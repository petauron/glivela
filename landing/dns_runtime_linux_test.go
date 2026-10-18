//go:build linux

package landing

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This uses the actual rendered policy, not a permissive test configuration.
// All apparently public addresses are aliases inside a fresh, unrouted netns.
func TestRenderedLandingDNSAndTLS(t *testing.T) {
	if os.Getenv("GLIVELA_LANDING_DNS_TEST") != "1" {
		t.Skip("isolated Linux namespace required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	initial, initialErr := os.Readlink("/proc/1/ns/net")
	if err != nil || initialErr != nil || current == initial || os.Geteuid() != 0 {
		t.Fatal("refusing test outside isolated root netns")
	}
	binary := os.Getenv("GLIVELA_XRAY_BINARY")
	if binary == "" {
		t.Fatal("verified official core required")
	}
	ipv6 := os.Getenv("GLIVELA_LANDING_FAMILY") == "ipv6"
	egress, targetNetwork, targetAddress, queryType := "192.168.50.2", "tcp4", "93.184.216.34:443", "A"
	if ipv6 {
		egress, targetNetwork, targetAddress, queryType = "2606:4700::100", "tcp6", "[::]:443", "AAAA"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture interface: %s %v", out, err)
		}
	}
	ip("link", "set", "lo", "up")
	for _, address := range []string{"100.64.0.10/32", "100.64.0.11/32", "100.64.0.12/32", "192.168.50.2/32", "93.184.216.34/32", "1.1.1.1/32", "1.0.0.1/32"} {
		ip("addr", "add", address, "dev", "lo")
	}
	if ipv6 {
		ip("-6", "addr", "add", egress+"/128", "dev", "lo", "nodad")
	}
	// The unprivileged worker needs traversal; no credentials are stored here.
	directory, err := os.MkdirTemp("", "glivela-isolated-dns-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	core, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	binary = filepath.Join(directory, "xray")
	if err := os.WriteFile(binary, core, 0755); err != nil {
		t.Fatal(err)
	}
	start := func(command *exec.Cmd) {
		t.Helper()
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	}
	dnsLog := filepath.Join(directory, "dns.log")
	args := []string{"--keep-in-foreground", "--conf-file=/dev/null", "--no-resolv", "--no-hosts", "--local-ttl=60", "--bind-interfaces", "--listen-address=1.1.1.1,1.0.0.1", "--user=root", "--pid-file=" + filepath.Join(directory, "dns.pid"), "--log-queries", "--log-facility=" + dnsLog}
	for i := 1; i <= 12; i++ {
		address := fmt.Sprintf("2001:db8::%x", i)
		if ipv6 {
			address = fmt.Sprintf("2606:4700::%x", i)
			ip("-6", "addr", "add", address+"/128", "dev", "lo", "nodad")
		}
		args = append(args, "--host-record=example.com,"+address)
	}
	args = append(args, "--host-record=example.com,93.184.216.34")
	args = append(args, "--host-record=private.example.com,192.168.50.2", "--host-record=mixed.example.com,192.168.50.2", "--host-record=mixed.example.com,93.184.216.34")
	args = append(args, "--host-record=ipv4only.example.com,93.184.216.34", "--host-record=unreachable.example.com,2606:4700::dead,93.184.216.34")
	if ipv6 {
		args = append(args, "--host-record=private.example.com,::1", "--host-record=mixed.example.com,::1", "--host-record=mixed.example.com,2606:4700::1")
	}
	start(exec.CommandContext(ctx, "dnsmasq", args...))
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "1.1.1.1:53")
	}}
	deadline := time.Now().Add(4 * time.Second)
	for {
		query, done := context.WithTimeout(ctx, 500*time.Millisecond)
		ips, err := resolver.LookupIP(query, "ip4", "example.com")
		done()
		if err == nil && len(ips) == 1 && ips[0].String() == "93.184.216.34" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DNS fixture unavailable", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if ips, err := resolver.LookupIP(ctx, "ip6", "example.com"); err != nil || len(ips) != 12 {
		t.Fatal("fixture must expose twelve IPv6 records", len(ips), err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != "example.com" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	_ = target.Listener.Close()
	target.Listener, err = net.Listen(targetNetwork, targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	target.StartTLS()
	defer target.Close()
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())
	blockedTargets := []string{"93.184.216.34:22", "192.168.50.2:443"}
	if ipv6 {
		blockedTargets = append(blockedTargets, "93.184.216.34:443", "[2606:4700::1]:22")
	}
	for _, address := range blockedTargets {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		_ = server.Listener.Close()
		server.Listener, err = net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		server.StartTLS()
		defer server.Close()
		pool.AddCert(server.Certificate())
		// Prove the blocked target is reachable and trusted without the proxy.
		direct := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "example.com"}}
		response, err := (&http.Client{Transport: direct, Timeout: time.Second}).Get("https://" + address)
		if err != nil {
			t.Fatal("blocked-target fixture not reachable", err)
		}
		response.Body.Close()
		direct.CloseIdleConnections()
	}
	plan := Plan{Revision: 1, Address: "100.64.0.10", EgressIP: egress, Sources: []Source{{Address: "100.64.0.11", TCPOnly: true}}}
	raw, err := plan.Render()
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(directory, "xray.json")
	if err := os.WriteFile(config, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := exec.CommandContext(ctx, binary, "run", "-test", "-config", config).Run(); err != nil {
		t.Fatal("official core rejected rendered policy", err)
	}
	const workerUID = 12345
	policy, err := plan.Firewall(workerUID, "lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Install(ctx); err != nil {
		t.Fatal(err)
	}
	worker := exec.CommandContext(ctx, binary, "run", "-config", config)
	worker.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: workerUID, Gid: workerUID, Groups: []uint32{}}}
	start(worker)
	proxy := &url.URL{Scheme: "socks5", Host: fmt.Sprintf("%s:%d", plan.Address, SOCKSPort)}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("100.64.0.11")}, Timeout: time.Second}
	deadline = time.Now().Add(4 * time.Second)
	for {
		conn, err := dialer.DialContext(ctx, "tcp", proxy.Host)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rendered listener unavailable", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", worker.Process.Pid))
	if err != nil || !strings.Contains(string(status), "\nUid:\t12345\t12345\t12345\t12345\n") {
		t.Fatal("fixture worker is not running under isolated non-root UID", err)
	}
	if err := policy.Verify(ctx); err != nil {
		t.Fatal("actual kernel policy missing", err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	countQueries := func() int {
		t.Helper()
		raw, err := os.ReadFile(dnsLog)
		if err != nil {
			t.Fatal("cannot read isolated DNS evidence", err)
		}
		return strings.Count(string(raw), "query["+queryType+"] example.com")
	}
	for _, phase := range []string{"cold", "warm"} {
		before := countQueries()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("actual rendered DNS/TLS failed (%s cache, resolver %s queries %d -> %d): %v", phase, queryType, before, countQueries(), err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatal("TLS target/SNI not reached", response.StatusCode)
		}
		if phase == "cold" && countQueries() <= before {
			t.Fatal("cold request never reached controlled resolver")
		}
		if phase == "warm" && countQueries() != before {
			t.Fatal("warm request did not use DNS cache")
		}
		t.Logf("%s cache: verified TLS/HTTP 204, resolver %s queries %d -> %d", phase, queryType, before, countQueries())
	}
	denials := []struct{ name, source, target string }{
		{"unauthorized-source", "100.64.0.12", "https://example.com/"},
		{"management-port", "100.64.0.11", "https://example.com:22/"},
		{"private-target", "100.64.0.11", "https://private.example.com/"},
		{"mixed-private-target", "100.64.0.11", "https://mixed.example.com/"},
	}
	if ipv6 {
		denials = append(denials, struct{ name, source, target string }{"no-ipv4-fallback", "100.64.0.11", "https://ipv4only.example.com/"}, struct{ name, source, target string }{"unreachable-ipv6-no-fallback", "100.64.0.11", "https://unreachable.example.com/"})
	}
	for _, denied := range denials {
		t.Run(denied.name, func(t *testing.T) {
			dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(denied.source)}, Timeout: time.Second}
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(denied.target)
			if err == nil {
				response.Body.Close()
				t.Fatal("restricted proxy request reached HTTP target")
			}
		})
	}
	untrusted := transport.Clone()
	untrusted.TLSClientConfig.RootCAs = x509.NewCertPool()
	defer untrusted.CloseIdleConnections()
	response, err := (&http.Client{Transport: untrusted, Timeout: 2 * time.Second}).Get("https://example.com/")
	if response != nil {
		response.Body.Close()
	}
	var authority x509.UnknownAuthorityError
	if !errors.As(err, &authority) {
		t.Fatal("untrusted certificate must fail specifically at TLS verification", err)
	}
}
