package control

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Uses an independently verified official binary. No production network,
// systemd service, firewall or existing application is touched by this test.
func TestOfficialXrayValidationAndTLS(t *testing.T) {
	binary := os.Getenv("GLIVELA_XRAY_BINARY")
	if binary == "" {
		t.Skip("set GLIVELA_XRAY_BINARY to a verified official Xray")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	driver := SystemdDriver{Binary: binary, BinarySHA256: hex.EncodeToString(digest[:])}
	if distribution := os.Getenv("GLIVELA_DISTRIBUTION"); distribution != "" {
		verified, err := (SystemdDriver{Distribution: distribution}).resolveDistribution(runtime.GOOS, runtime.GOARCH)
		if err != nil || verified.Binary != driver.Binary || verified.BinarySHA256 != driver.BinarySHA256 {
			t.Fatal("packaged runtime metadata does not identify the tested core", err)
		}
		driver = verified
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	path := filepath.Join(t.TempDir(), "xray.json")
	// Loopback forwarding is intentional in this isolated fixture; production
	// landing safety rules must be validated separately, not weakened for it.
	// Exercise a mixed resolver inventory larger than the legacy adapter's
	// address window. The IPv4 result must remain usable even when it is last.
	var records []string
	for i := 1; i <= 12; i++ {
		records = append(records, fmt.Sprintf("2001:db8::%x", i))
	}
	records = append(records, "127.0.0.1")
	hosts, err := json.Marshal(map[string][]string{"example.com": records})
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`{"log":{"loglevel":"none"},"dns":{"hosts":%s,"queryStrategy":"UseIPv4"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],"outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}]}`, hosts, port)
	if err = os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = driver.Validate(ctx, path); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, "run", "-config", path)
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = command.Wait() }()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer target.Close()
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())
	if err := target.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatal("TLS fixture lacks domain identity", err)
	}
	domainURL := strings.Replace(target.URL, "127.0.0.1", "example.com", 1)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = probeSOCKSTLS(ctx, address, target.URL, pool)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := probeSOCKSTLS(ctx, address, domainURL, pool); err != nil {
		t.Fatal("IPv4 SOCKS domain request failed with twelve preceding IPv6 records", err)
	}
	if probeSOCKSTLS(ctx, address, domainURL, nil) == nil {
		t.Fatal("domain request skipped certificate verification")
	}
	if probeSOCKSTLS(ctx, address, target.URL, nil) == nil {
		t.Fatal("untrusted TLS target accepted")
	}
	exitTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("203.0.113.9\n")) }))
	defer exitTarget.Close()
	pool.AddCert(exitTarget.Certificate())
	probe := RouteProbe{AttemptID: "attempt-example", SnapshotID: "snapshot-example", EntryID: "entry-example", LandingID: "landing-example", Revision: 7, ConfigSHA256: strings.Repeat("a", 64), SOCKSAddress: address, Target: strings.Replace(exitTarget.URL, "127.0.0.1", "example.com", 1), ExpectedExit: "203.0.113.9"}
	result, err := checkRoute(ctx, probe, pool)
	if err != nil || !result.Passed || !result.TLSVerified || result.HTTPStatus != 200 || result.Revision != 7 || result.SnapshotID != probe.SnapshotID {
		t.Fatal("entry-side route acceptance failed", err, result.Failure)
	}
	probe.ExpectedExit = "203.0.113.10"
	result, err = checkRoute(ctx, probe, pool)
	if err == nil || result.Passed || !result.TLSVerified || result.Failure != "exit-mismatch" {
		t.Fatal("wrong exit accepted")
	}
	probe.Target = domainURL
	result, err = checkRoute(ctx, probe, pool)
	if err == nil || result.Passed || !result.TLSVerified || result.HTTPStatus != 404 || result.Failure != "http-status" {
		t.Fatal("HTTP rejection confused with TLS failure")
	}
	result, err = checkRoute(ctx, probe, nil)
	if err == nil || result.Passed || result.TLSVerified || result.HTTPStatus != 0 {
		t.Fatal("untrusted certificate accepted by route check")
	}
	if err = os.WriteFile(path, []byte(`{"inbounds":[{"protocol":"invalid"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if driver.Validate(ctx, path) == nil {
		t.Fatal("invalid Xray config accepted")
	}
}
