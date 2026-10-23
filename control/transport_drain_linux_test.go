//go:build linux

package control

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOfficialXrayDrainKeepsEstablishedStream(t *testing.T) {
	driver := officialTestDriver(t)
	continued := make(chan struct{}, 1)
	defer close(continued)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "before-drain")
		w.(http.Flusher).Flush()
		select {
		case <-continued:
		case <-r.Context().Done():
			return
		}
		fmt.Fprintln(w, "after-drain")
	}))
	defer target.CloseClientConnections()
	defer target.Close()
	port, api := quotaLoopbackPort(t), quotaLoopbackPort(t)
	config := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"api": map[string]any{"tag": "api", "services": []string{"HandlerService"}},
		"inbounds": []any{
			map[string]any{"tag": "business", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}},
			map[string]any{"tag": "api", "listen": "127.0.0.1", "port": api, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}},
		},
		"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"}}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}, map[string]any{"action": "block", "ip": []string{"0.0.0.0/0", "::/0"}}}}}},
	}
	startQuotaTestCore(t, driver.Binary, config, port)
	proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "before-drain\n" {
		t.Fatal("stream not established", err)
	}
	if _, err := nativeEntryCommand(context.Background(), driver.Binary, "api", "rmi", fmt.Sprintf("--server=127.0.0.1:%d", api), "business"); err != nil {
		t.Fatal(err)
	}
	if connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		connection.Close()
		t.Fatal("new connection admitted during drain")
	}
	continued <- struct{}{}
	if line, err := reader.ReadString('\n'); err != nil || line != "after-drain\n" {
		t.Fatal("established stream interrupted by listener removal", err)
	}
}

func TestTransportDrainRequiresNoOwnedBusinessSockets(t *testing.T) {
	row := func(local, state, inode string) string {
		return " 0: " + local + " 00000000:0000 " + state + " 0:0 00:0 0 1001 0 " + inode + "\n"
	}
	owned := map[string]bool{"10": true, "11": true}
	api := row("0100007F:2765", "0A", "10")
	for _, test := range []struct {
		name, network, raw string
		want               bool
	}{
		{"api only", "tcp", api, true},
		{"other service", "tcp", api + row("00000000:01BB", "01", "99"), true},
		{"active tcp", "tcp", api + row("0100007F:01BB", "01", "11"), false},
		{"remaining proxy listener", "tcp", api + row("0100007F:01BB", "0A", "11"), false},
		{"api request still active", "tcp", api + row("0100007F:2765", "01", "11"), false},
		{"active udp", "udp", row("00000000:01BB", "07", "11"), false},
		{"active ipv6", "tcp6", row("00000000000000000000000000000000:01BB", "01", "11"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := drainedSocketTable(strings.NewReader(test.raw), owned, test.network)
			if err != nil || got != test.want {
				t.Fatal(got, err)
			}
		})
	}
	if _, err := drainedSocketTable(strings.NewReader("truncated\n"), owned, "tcp"); err == nil {
		t.Fatal("malformed socket evidence accepted")
	}
}
