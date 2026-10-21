package control

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// This exercises the rendered credential inventory against the official core,
// not merely JSON presence. The transport is loopback VLESS without REALITY so
// the test needs no public decoy or privileged service. It proves authentication
// denial/recovery, NOT production REALITY, firewall or systemd acceptance.
func TestOfficialXrayEntryQuotaDeniesAndRestoresConnections(t *testing.T) {
	driver := officialTestDriver(t)
	q, desired, now := quotaFixture(t)
	q, blocked, err := advanceEntryQuota(q, desired, quotaReceipt(desired, now, now.Add(time.Second), 25), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, restored, err := advanceEntryQuota(q, blocked, nil, q.NextResetAt)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	for _, scenario := range []struct {
		name    string
		desired Desired
		allowed bool
	}{{"before-limit", desired, true}, {"over-limit", blocked, false}, {"next-cycle", restored, true}} {
		t.Run(scenario.name, func(t *testing.T) {
			var rendered map[string]any
			if err := json.Unmarshal(scenario.desired.Config, &rendered); err != nil {
				t.Fatal(err)
			}
			var clients []any
			for _, item := range rendered["inbounds"].([]any) {
				inbound := item.(map[string]any)
				if inbound["protocol"] != "vless" {
					continue
				}
				clients = inbound["settings"].(map[string]any)["clients"].([]any)
				for _, client := range clients {
					delete(client.(map[string]any), "flow")
				}
			}
			serverPort := quotaLoopbackPort(t)
			server := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": serverPort, "protocol": "vless", "settings": map[string]any{"clients": clients, "decryption": "none"}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
			// The pinned core blocks private targets by default. Permit only
			// this loopback fixture, never relax production outbound policy.
			server["outbounds"] = []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{
				map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}},
				map[string]any{"action": "block", "ip": []string{"0.0.0.0/0", "::/0"}},
			}}}}
			startQuotaTestCore(t, driver.Binary, server, serverPort)
			clientPort := quotaLoopbackPort(t)
			client := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": clientPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": serverPort, "users": []any{map[string]any{"id": desired.Entry.Credentials[0].ProtocolID, "encryption": "none"}}}}}}}}
			startQuotaTestCore(t, driver.Binary, client, clientPort)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := probeSOCKSTLS(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)), target.URL, roots)
			if (err == nil) != scenario.allowed {
				t.Fatalf("authenticated connection allowed=%v, want=%v: %v", err == nil, scenario.allowed, err)
			}
		})
	}
}

func quotaLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func startQuotaTestCore(t *testing.T, binary string, config any, port int) {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "core.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binary, "run", "-config", path)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = command.Wait()
		if t.Failed() {
			t.Log(output.String())
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("isolated Xray did not start")
}
