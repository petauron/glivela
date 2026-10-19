//go:build linux

package control

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

// Native-core policy proof only. All aliases and resolver processes are inside
// the caller's guarded unrouted namespaces. This does not prove Docker/UID,
// public ingress or authorized application UDP enforcement.
func exerciseEntryNativeTargetSafety(t *testing.T, ctx context.Context, driver SystemdDriver, desired Desired, front string, target *httptest.Server, roots *x509.CertPool, publicRequests *atomic.Int64, stopOriginalDNS func()) {
	t.Helper()
	ip := func(args ...string) {
		t.Helper()
		if err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).Run(); err != nil {
			t.Fatal("native safety alias setup failed", err)
		}
	}
	ip("addr", "add", "192.168.50.2/32", "dev", "lo")
	ip("-6", "addr", "add", "2606:4700::100/128", "dev", "lo", "nodad")
	var privateRequests, privateConnections, v6Requests atomic.Int64
	_, port, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsTarget := func(address string, count, connections *atomic.Int64) *httptest.Server {
		t.Helper()
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); w.WriteHeader(204) }))
		s.Listener.Close()
		var err error
		s.Listener, err = net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		if connections != nil {
			s.Listener = &nativeTargetAcceptCounter{Listener: s.Listener, count: connections}
		}
		s.TLS = target.TLS.Clone()
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	tlsTarget(net.JoinHostPort("192.168.50.2", port), &privateRequests, &privateConnections)
	tlsTarget(net.JoinHostPort("2606:4700::100", port), &v6Requests, nil)
	startWorker := func(t *testing.T, d Desired) func() {
		t.Helper()
		path := filepath.Join(t.TempDir(), "entry.json")
		if err := os.WriteFile(path, d.Config, 0600); err != nil {
			t.Fatal(err)
		}
		return startAuthenticationCore(t, ctx, driver, path, net.JoinHostPort(d.Entry.RealityEndpoints[0].ListenAddress, fmt.Sprint(d.Entry.RealityEndpoints[0].ListenPort)))
	}
	client := startRealityClientFixture(t, ctx, driver, desired.Entry.RealityEndpoints[0], front, desired.Entry.Credentials[0].ProtocolID)
	stop := startWorker(t, desired)
	if err := probeAuthenticatedEntry(ctx, client, target.URL, roots); err != nil {
		t.Fatal("public DNS control did not succeed", err)
	}
	stopOriginalDNS()
	privateLog := filepath.Join(t.TempDir(), "private-dns.log")
	stopPrivate := startEntryResolverFixture(t, ctx, "192.168.50.2", privateLog)
	// Keep the same worker running across the resolver change. Cached public
	// addresses may remain safe until TTL expiry, but no private connection is
	// permitted after an actual fresh private DNS answer.
	deadline := time.Now().Add(8 * time.Second)
	for {
		err := probeAuthenticatedEntry(ctx, client, target.URL, roots)
		if privateRequests.Load() != 0 || privateConnections.Load() != 0 {
			t.Fatal("rebinding reached a private TLS target")
		}
		log, _ := os.ReadFile(privateLog)
		if err != nil && strings.Contains(string(log), "query[A] example.com") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("private rebinding response was not exercised")
		}
		time.Sleep(150 * time.Millisecond)
	}
	stopPrivate()
	stopPublic := startEntryResolverFixture(t, ctx, "93.184.216.34", filepath.Join(t.TempDir(), "restored-dns.log"))
	deadline = time.Now().Add(8 * time.Second)
	for {
		err := probeAuthenticatedEntry(ctx, client, target.URL, roots)
		if err == nil {
			break
		}
		if privateRequests.Load() != 0 || privateConnections.Load() != 0 || time.Now().After(deadline) {
			t.Fatal("same worker did not recover when public DNS returned", err)
		}
		time.Sleep(150 * time.Millisecond)
	}
	stop()
	stopPublic()
	stopDual := startEntryResolverFixture(t, ctx, "93.184.216.34,2606:4700::100", filepath.Join(t.TempDir(), "dual-dns.log"))
	defer stopDual()
	var literal4, literal6, literal4Connections, literal6Connections atomic.Int64
	plainTarget := func(address string, count, connections *atomic.Int64) *httptest.Server {
		t.Helper()
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); w.WriteHeader(204) }))
		s.Listener.Close()
		var err error
		s.Listener, err = net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		s.Listener = &nativeTargetAcceptCounter{Listener: s.Listener, count: connections}
		s.Start()
		t.Cleanup(s.Close)
		return s
	}
	plain4 := plainTarget("93.184.216.34:0", &literal4, &literal4Connections)
	plain6 := plainTarget("[2606:4700::100]:0", &literal6, &literal6Connections)
	for index, policy := range []glivela.EgressPolicy{glivela.EgressIPv4Only, glivela.EgressIPv6Only} {
		t.Run(string(policy), func(t *testing.T) {
			plan := *desired.clone().Entry
			plan.NativeEgress = policy
			plan.Revision += uint64(index + 1)
			d, err := NewEntryDesired(plan, *desired.EntryNetwork)
			if err != nil {
				t.Fatal(err)
			}
			stop := startWorker(t, d)
			defer stop()
			before4, before6 := publicRequests.Load(), v6Requests.Load()
			if err := probeAuthenticatedEntry(ctx, client, target.URL, roots); err != nil {
				t.Fatal("selected family HTTPS did not succeed", err)
			}
			if policy == glivela.EgressIPv4Only && (publicRequests.Load() != before4+1 || v6Requests.Load() != before6) || policy == glivela.EgressIPv6Only && (v6Requests.Load() != before6+1 || publicRequests.Load() != before4) {
				t.Fatal("native domain policy crossed address families")
			}
			allowed, denied, allowedCount, deniedCount := plain4.URL, plain6.URL, &literal4, &literal6
			deniedConnections := &literal6Connections
			if policy == glivela.EgressIPv6Only {
				allowed, denied, allowedCount, deniedCount = plain6.URL, plain4.URL, &literal6, &literal4
				deniedConnections = &literal4Connections
			}
			beforeAllowed, beforeDenied := allowedCount.Load(), deniedCount.Load()
			beforeDeniedConnections := deniedConnections.Load()
			if err := probeLiteralEntry(ctx, client, allowed); err != nil || allowedCount.Load() != beforeAllowed+1 {
				t.Fatal("selected literal family did not work", err)
			}
			if err := probeLiteralEntry(ctx, client, denied); err == nil || deniedCount.Load() != beforeDenied || deniedConnections.Load() != beforeDeniedConnections {
				t.Fatal("opposite literal family reached the target")
			}
		})
	}
	if privateRequests.Load() != 0 || privateConnections.Load() != 0 {
		t.Fatal("private target was reached")
	}
	if literal4Connections.Load() != 1 || literal6Connections.Load() != 1 {
		t.Fatal("opposite family established a TCP connection")
	}
}

type nativeTargetAcceptCounter struct {
	net.Listener
	count *atomic.Int64
}

func (l *nativeTargetAcceptCounter) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.count.Add(1)
	}
	return connection, err
}

// Intentionally plain HTTP to an IP literal: no SNI/hostname override can turn
// the destination into a different family. HTTPS/SNI/cert checks are separate
// positive/negative controls above; no certificate verification is disabled.
func probeLiteralEntry(ctx context.Context, socks, target string) error {
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: socks}), DisableKeepAlives: true, ResponseHeaderTimeout: 2 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 204 {
		return fmt.Errorf("unexpected literal target status")
	}
	return nil
}
