package control

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
	config := fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],"outbounds":[{"protocol":"freedom"}]}`, port)
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
	if probeSOCKSTLS(ctx, address, target.URL, nil) == nil {
		t.Fatal("untrusted TLS target accepted")
	}
	if err = os.WriteFile(path, []byte(`{"inbounds":[{"protocol":"invalid"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if driver.Validate(ctx, path) == nil {
		t.Fatal("invalid Xray config accepted")
	}
}
