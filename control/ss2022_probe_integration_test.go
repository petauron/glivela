package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// Reuses an explicitly supplied official core. No download, container, public
// listener, production credential or external HTTP endpoint is used.
func TestSS2022ProbeWithOfficialCore(t *testing.T) {
	t.Run("loopback", func(t *testing.T) { testSS2022ProbeWithOfficialCore(t, false) })
	if os.Getenv("GLIVELA_TEST_TRANSPORT_FENCE") == "1" {
		t.Run("public-endpoint", func(t *testing.T) { testSS2022ProbeWithOfficialCore(t, true) })
	}
}

func testSS2022ProbeWithOfficialCore(t *testing.T, public bool) {
	binary := os.Getenv("GLIVELA_TEST_XRAY")
	if binary == "" {
		t.Skip("official Xray not supplied")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "8.8.8.8") }))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	listenAddress := "127.0.0.1"
	if public {
		current, err := os.Readlink("/proc/self/ns/net")
		initial, initialErr := os.Readlink("/proc/1/ns/net")
		if err != nil || initialErr != nil || current == initial || os.Geteuid() != 0 {
			t.Fatal("isolated namespace required for synthetic public address")
		}
		if err := exec.Command("ip", "address", "add", "8.8.4.4/32", "dev", "lo").Run(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = exec.Command("ip", "address", "del", "8.8.4.4/32", "dev", "lo").Run() }()
		listenAddress, port, address = "8.8.4.4", 1080, "8.8.4.4:1080"
	}
	key := "AAECAwQFBgcICQoLDA0ODw=="
	config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": listenAddress, "port": port, "protocol": "shadowsocks", "settings": map[string]any{"method": glivela.SS2022Method, "password": key, "network": "tcp"}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	apiListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiAddress := apiListener.Addr().String()
	apiPort := apiListener.Addr().(*net.TCPAddr).Port
	_ = apiListener.Close()
	proxyInbound := config["inbounds"].([]any)[0].(map[string]any)
	proxyInbound["tag"] = "probe-server"
	config["inbounds"] = []any{proxyInbound, map[string]any{"listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}, "tag": "api"}}
	config["api"] = map[string]any{"tag": "api", "services": []string{"HandlerService"}}
	config["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"}}}
	// The synthetic TLS target is loopback. Permit only its exact port in this
	// test fixture; production landing isolation is deliberately unchanged.
	config["outbounds"] = []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": target.Listener.Addr().(*net.TCPAddr).Port}}}}}
	data, _ := json.Marshal(config)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "run", "-config", "stdin:")
	cmd.Stdin = bytes.NewReader(data)
	var coreLog bytes.Buffer
	cmd.Stdout = &coreLog
	cmd.Stderr = &coreLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	for i := 0; i < 100; i++ {
		c, e := net.DialTimeout("tcp", address, 20*time.Millisecond)
		if e == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	p := RouteProbe{AttemptID: "test-attempt", SnapshotID: "test-snapshot", EntryID: "test-entry", LandingID: "test-landing", Revision: 1, ConfigSHA256: strings.Repeat("a", 64), SOCKSAddress: address, Target: target.URL, ExpectedExit: "8.8.8.8", Transport: glivela.PrivateTransport{Protocol: "ss2022", Key: key}}
	if public {
		p.Transport.PublicAddress = listenAddress
	}
	result, err := probeWithCore(ctx, p, binary, digest, roots)
	if err != nil || !result.Passed || !result.TLSVerified || result.ObservedExit != p.ExpectedExit {
		cancel()
		_ = cmd.Wait()
		t.Log(coreLog.String())
		t.Fatalf("real SS2022 probe did not pass: %+v %v", result, err)
	}
	if os.Getenv("GLIVELA_TEST_TRANSPORT_FENCE") == "1" {
		fence := landing.TransportFence{Binding: "isolated-ss2022-integration", Listeners: []landing.TransportListener{{Address: listenAddress, Port: port, Network: "tcp"}}}
		if err := fence.Install(ctx); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			if err := fence.Remove(cleanup); err != nil {
				t.Error("test fence cleanup failed", err)
			}
		}()
		blocked := func() {
			t.Helper()
			if err := fence.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			probeCtx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
			defer stop()
			if result, err := probeWithCore(probeCtx, p, binary, digest, roots); err == nil || result.Passed {
				t.Fatal("client traffic crossed maintenance fence")
			}
		}
		blocked()
		remove := exec.CommandContext(ctx, binary, "api", "rmi", "--server="+apiAddress, "probe-server")
		remove.Stdout, remove.Stderr = io.Discard, io.Discard
		if err := remove.Run(); err != nil {
			t.Fatal("actual inbound drain failed", err)
		}
		restoreData, _ := json.Marshal(map[string]any{"inbounds": []any{proxyInbound}})
		restore := exec.CommandContext(ctx, binary, "api", "adi", "--server="+apiAddress)
		restore.Stdin = bytes.NewReader(restoreData)
		restore.Stdout, restore.Stderr = io.Discard, io.Discard
		if err := restore.Run(); err != nil {
			t.Fatal("same-process inbound restoration failed", err)
		}
		blocked()
		// Restart the actual core while the independent maintenance fence stays
		// installed, modelling candidate start and configuration restoration.
		if err := cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = cmd.Wait()
		cmd = exec.CommandContext(ctx, binary, "run", "-config", "stdin:")
		cmd.Stdin = bytes.NewReader(data)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		blocked()
		if err := fence.Remove(ctx); err != nil {
			t.Fatal(err)
		}
		if result, err := probeWithCore(ctx, p, binary, digest, roots); err != nil || !result.Passed {
			t.Fatal("restored core failed after fence removal", err)
		}
		t.Log("actual Xray restart remained fenced; verified TLS route restored after removal")
	}
	p.ExpectedExit = "1.1.1.1"
	if result, err := probeWithCore(ctx, p, binary, digest, roots); err == nil || result.Passed || result.Failure != "exit-mismatch" {
		t.Fatal("unexpected exit accepted")
	}
	p.ExpectedExit = "8.8.8.8"
	if result, err := probeWithCore(ctx, p, binary, digest, nil); err == nil || result.Passed || result.Failure != "certificate-verification" {
		t.Fatal("untrusted certificate accepted")
	}
	p.Transport.Key = "EBESExQVFhcYGRobHB0eHw=="
	wrong, done := context.WithTimeout(ctx, 2*time.Second)
	defer done()
	if result, err := probeWithCore(wrong, p, binary, digest, roots); err == nil || result.Passed {
		t.Fatal("wrong key accepted or silently fell back")
	}
}
