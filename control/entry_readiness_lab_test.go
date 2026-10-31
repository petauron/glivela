package control

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/petauron/glivela"
)

// Opt-in real-core acceptance. Only run in the dedicated CT116; uses synthetic
// identities and loopback listeners. Apple is the external REALITY target.
func TestEntryReadinessLab(t *testing.T) {
	if os.Getenv("GLIVELA_READINESS_LAB") != "1" {
		t.Skip("requires isolated CT116")
	}
	binary := os.Getenv("GLIVELA_XRAY_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("explicit Xray binary required")
	}
	var healthy atomic.Bool
	healthy.Store(true)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(503)
			return
		}
		fmt.Fprint(w, "ip=203.0.113.9\n")
	}))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := glivela.RealityEndpoint{AdvertiseHost: "127.0.0.1", ServerNames: []string{"www.apple.com"}, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortIDs: []string{"aabbccdd"}, Fingerprint: "chrome"}
	material := glivela.CredentialMaterial{ProtocolID: "abcf1234-1234-4123-8123-123456789abc"}
	for round := 0; round < 4; round++ {
		t.Run(fmt.Sprint(round+1), func(t *testing.T) {
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			endpoint.AdvertisePort = l.Addr().(*net.TCPAddr).Port
			l.Close()
			raw, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": endpoint.AdvertisePort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": material.ProtocolID, "flow": "xtls-rprx-vision"}}, "decryption": "none"}, "streamSettings": map[string]any{"network": "tcp", "rawSettings": map[string]any{"acceptProxyProtocol": true}, "security": "reality", "realitySettings": map[string]any{"target": "www.apple.com:443", "serverNames": endpoint.ServerNames, "privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": endpoint.ShortIDs}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": fmt.Sprint(target.Listener.Addr().(*net.TCPAddr).Port)}}}}}})
			config := filepath.Join(t.TempDir(), "server.json")
			if err := os.WriteFile(config, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "run", "-c", config)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = command.Wait() }()
			// Listener readiness, not initialization sleep.
			for until := time.Now().Add(time.Second); ; {
				c, err := net.DialTimeout("tcp", net.JoinHostPort(endpoint.AdvertiseHost, fmt.Sprint(endpoint.AdvertisePort)), 50*time.Millisecond)
				if err == nil {
					c.Close()
					break
				}
				if time.Now().After(until) {
					t.Fatal("listener unavailable")
				}
				time.Sleep(10 * time.Millisecond)
			}
			advertised := endpoint
			advertised.ListenAddress, advertised.ListenPort = "127.0.0.1", endpoint.AdvertisePort
			advertised.AdvertiseHost, advertised.AdvertisePort = "203.0.113.254", 1
			local, err := nativeWarmupPlan(Desired{Entry: &glivela.XrayPlan{RealityEndpoints: []glivela.RealityEndpoint{advertised}}})
			if err != nil {
				t.Fatal(err)
			}
			endpoint = local.RealityEndpoints[0]
			var gate entryReadiness
			generation := fmt.Sprintf("%d:%d:config", round, command.Process.Pid)
			identity := func() (string, error) { return generation, nil }
			probe := func(ctx context.Context) error {
				return probeRealityClient(ctx, binary, endpoint, material, endpoint.ServerNames[0], target.URL, roots, true)
			}
			start := time.Now()
			if err := gate.check(ctx, identity, probe); err != nil {
				t.Fatal(err)
			}
			t.Logf("ready after %s", time.Since(start))
			start = time.Now()
			if err := probe(ctx); err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(start)
			t.Logf("fresh user client including two HTTPS connections: %s", elapsed)
			if elapsed > 2*time.Second {
				t.Fatal("initialization delay leaked past readiness")
			}
			healthy.Store(false)
			generation += "changed"
			if err := gate.check(ctx, identity, probe); err == nil || gate.accepted != "" {
				t.Fatal("503 accepted as ready")
			}
			healthy.Store(true)
		})
	}
}
