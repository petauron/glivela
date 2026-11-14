//go:build linux

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	glivela "github.com/petauron/glivela"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Optional real-engine acceptance is called by the matching owned-Caddy lab.
// All apparently public addresses exist only inside a NIC-free test namespace.
func TestPublic443CoreLAB(t *testing.T) {
	if os.Getenv("GLIVELA_PUBLIC443_LAB") != "1" {
		t.Skip("explicit isolated443 lab required")
	}
	current, e := os.Readlink("/proc/self/ns/net")
	initial, e2 := os.Readlink("/proc/1/ns/net")
	marker, e3 := os.ReadFile("/run/glivela-public443-lab.allowed")
	if e != nil || e2 != nil || current == initial || e3 != nil || string(marker) != "synthetic-no-nic-only\n" || os.Geteuid() != 0 {
		t.Fatal("refuse unisolated public443 test")
	}
	driver := officialTestDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dualEnabled := os.Getenv("GLIVELA_PUBLIC443_DUAL") == "1"
	var dual atomic.Bool
	dual.Store(dualEnabled)
	publicIngressResolver(t, &dual)
	s, endpoint, _ := publicIngressFixture(t)
	// The synthetic account needs room for TLS records and both family requests.
	seed := s.business.material
	seed.Plan.Accounts[0].Account.Plan.TotalBytes = 1 << 30
	var err error
	seed.Plan, err = glivela.PlanImport(seed.Plan.Accounts)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.saveOwnedBusinessLocked(seed); err != nil {
		t.Fatal(err)
	}
	before := s.business.material
	resource := ManagedIngressResource{ID: "resource-example", Hostname: endpoint.Reality.AdvertiseHost, Address: endpoint.Reality.ListenAddress, Type: "AAAA", Revision: 2, AppliedRevision: 2, Status: "ready"}
	if dualEnabled {
		resource.SecondaryAddress = "1.1.1.1"
	}
	raw, _ := json.Marshal(resource)
	view, err := s.ChangePublicIngress(ctx, PublicIngressChange{EntryID: endpoint.Reality.EntryID, Action: "apply", ExpectedRevision: endpoint.DesiredRevision, Resource: raw})
	if err != nil {
		t.Fatal(err)
	}
	cert := strings.Repeat("a", 64)
	desired := s.nodes[cert].Desired.clone()
	roots := x509.NewCertPool()
	ca, err := os.ReadFile(os.Getenv("GLIVELA_PUBLIC443_CA"))
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("synthetic site CA missing")
	}
	origin := public443Origin(t, "8.8.4.4")
	defer origin.Close()
	originRoots := x509.NewCertPool()
	originRoots.AddCert(origin.Certificate())
	root := t.TempDir()
	start := func(name string, config []byte) (*exec.Cmd, func()) {
		path := filepath.Join(root, name+".json")
		if err := os.WriteFile(path, config, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, driver.Binary, "run", "-config", path)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				_ = command.Process.Kill()
				_ = command.Wait()
			}
		}
		t.Cleanup(stop)
		return command, stop
	}
	// SS is a separate original24000 listener. It stays alive with the same key
	// and PID throughout the VLESS transition and forward recovery.
	ssConfig, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "9.9.9.9", "port": 24000, "protocol": "shadowsocks", "settings": map[string]any{"method": glivela.SS2022Method, "password": "AAECAwQFBgcICQoLDA0ODw==", "network": "tcp"}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}})
	ss, stopSS := start("ss24000", ssConfig)
	defer stopSS()
	ssPID := ss.Process.Pid
	startedAt := time.Now().UTC().Format(time.RFC3339Nano)
	_, stopServer := start("entry443", desired.Config)
	defer stopServer()
	counter := func() *EntryTraffic {
		data, e := exec.CommandContext(ctx, driver.Binary, "api", "statsquery", "--server=127.0.0.1:10085").Output()
		if e != nil {
			t.Fatal("core counters unavailable")
		}
		sample, e := parseEntryTraffic(data, desired, startedAt)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Exchange(ctx, cert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: desired.Revision, ConfigSHA256: desired.ConfigSHA256, RuntimeReady: true}, Traffic: sample}); e != nil {
			t.Fatal("aggregate usage rejected", e)
		}
		return sample
	}
	wait443(t, ctx, endpoint.Reality.ListenAddress, 443)
	user := desired.Entry.Credentials[0]
	for _, candidate := range desired.Entry.Credentials {
		if candidate.Credential.AccountID == "account-example" {
			user = candidate
			break
		}
	}
	// Use the production startup probe before publishing readiness. Its first
	// request has the existing initialization budget; subsequent user requests
	// retain their normal four-second limit. Only the TLS-verified origin is synthetic.
	for _, address := range []string{endpoint.Reality.ListenAddress, view.IPv4ListenAddress} {
		if address == "" {
			continue
		}
		warm := endpoint.Reality
		warm.AdvertiseHost, warm.AdvertisePort = address, 443
		if err := probeRealityClient(ctx, driver.Binary, warm, user, warm.ServerNames[0], origin.URL, originRoots, false, desired.Entry.NativeEgress); err != nil {
			t.Fatal("production startup warmup", err)
		}
	}
	// Fetch the actual subscription renderer, not a hand-written VLESS identity.
	reportRuntime(t, s, cert, desired)
	// The plain share format preserves the same retained token and UUID.
	plain := getSubscription(t, s, "/sub/example-token", "")
	if plain.Code != 200 {
		t.Fatal("retained subscription failed")
	}
	currentReality := s.business.material.Endpoints[0].Reality
	if currentReality.AdvertisePort != 443 || currentReality.AdvertiseHost != endpoint.Reality.AdvertiseHost || currentReality.PrivateKey != endpoint.Reality.PrivateKey {
		t.Fatal("subscription or key changed")
	}
	decoded, e := base64.StdEncoding.DecodeString(plain.Body.String())
	if e != nil {
		t.Fatal("share encoding", e)
	}
	var share *url.URL
	for _, line := range strings.Split(strings.TrimSpace(string(decoded)), "\n") {
		u, e := url.Parse(line)
		if e == nil && u.Scheme == "vless" && u.User.Username() == user.ProtocolID {
			share = u
			break
		}
	}
	if share == nil || share.Port() != "443" || share.Hostname() != currentReality.AdvertiseHost || share.Query().Get("sni") != currentReality.ServerNames[0] || share.Query().Get("pbk") != currentReality.PublicKey {
		t.Fatal("formal share lost retained identity or443")
	}
	// Parse the actual retained Mihomo feed as well as the public VLESS share.
	feed := getSubscription(t, s, "/sub/example-token?format=mihomo", "")
	var parsed struct {
		Proxies []struct {
			Server     string `yaml:"server"`
			Port       int    `yaml:"port"`
			UUID       string `yaml:"uuid"`
			ServerName string `yaml:"servername"`
		}
	}
	if feed.Code != 200 || yaml.Unmarshal(feed.Body.Bytes(), &parsed) != nil {
		t.Fatal("Mihomo subscription unavailable")
	}
	found := false
	for _, proxy := range parsed.Proxies {
		if proxy.UUID == user.ProtocolID {
			found = true
			if proxy.Server != currentReality.AdvertiseHost || proxy.Port != 443 || proxy.ServerName != currentReality.ServerNames[0] {
				t.Fatal("Mihomo endpoint changed identity")
			}
		}
	}
	if !found {
		t.Fatal("retained identity absent from Mihomo feed")
	}
	target := origin.URL
	clientFor := func(address string, port int, secret string) (string, func()) {
		listener, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		socks := listener.Addr().String()
		p := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		outbound := map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": address, "port": port, "users": []any{map[string]any{"id": secret, "flow": "xtls-rprx-vision", "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": currentReality.ServerNames[0], "fingerprint": "chrome", "publicKey": currentReality.PublicKey, "shortId": currentReality.ShortIDs[0]}}}
		config, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": p, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{outbound}})
		_, stop := start(fmt.Sprintf("client-%d", p), config)
		wait443(t, ctx, "127.0.0.1", p)
		return socks, stop
	}
	request := func(socks string, want bool) {
		dialer, e := proxy.SOCKS5("tcp", socks, nil, &net.Dialer{Timeout: 2 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			return dialer.(proxy.ContextDialer).DialContext(ctx, n, a)
		}, TLSClientConfig: &tls.Config{RootCAs: originRoots, MinVersion: tls.VersionTLS13}}
		client := &http.Client{Timeout: 4 * time.Second, Transport: transport}
		defer transport.CloseIdleConnections()
		response, e := client.Get(target)
		if !want {
			if e == nil {
				response.Body.Close()
				t.Fatal("unauthorized credential reached origin")
			}
			return
		}
		if e != nil {
			t.Fatal("real proxy request failed", e)
		}
		body, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil || response.StatusCode != 200 || string(body) != "ip=8.8.4.4\n" {
			t.Fatal("proxy TLS/body invalid")
		}
	}
	normalTLS := func(address string) {
		transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "site.example.test", MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(address, "443"))
		}}
		defer transport.CloseIdleConnections()
		response, e := (&http.Client{Timeout: 5 * time.Second, Transport: transport}).Get("https://site.example.test/")
		if e != nil {
			t.Fatal("ordinary HTTPS fallback", e)
		}
		body, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil || response.StatusCode != 200 || response.ProtoMajor != 2 || string(body) != "synthetic owned website" {
			t.Fatal("ordinary H2 fallback lost website", response.StatusCode, response.Proto)
		}
	}
	addresses := []string{endpoint.Reality.ListenAddress}
	if dualEnabled {
		addresses = append(addresses, "1.1.1.1")
	}
	first := counter()
	for _, address := range addresses {
		normalTLS(address)
		socks, stop := clientFor(address, 443, user.ProtocolID)
		request(socks, true)
		stop()
		next := counter()
		id := user.Credential.ID
		if next.Counters[id].Upload <= first.Counters[id].Upload || next.Counters[id].Download <= first.Counters[id].Download {
			t.Fatal("family did not contribute to the same user counter")
		}
		first = next
	}
	// The parent performs a real Caddy content refresh while Xray owns443.
	ready := os.Getenv("GLIVELA_PUBLIC443_READY")
	resume := os.Getenv("GLIVELA_PUBLIC443_RESUME")
	if ready == "" || resume == "" {
		t.Fatal("missing parent handoff")
	}
	if e = os.WriteFile(ready, []byte("ready"), 0600); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		if _, e = os.Stat(resume); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parent content refresh did not complete")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, address := range addresses {
		normalTLS(address)
		socks, stop := clientFor(address, 443, "99999999-9999-4999-8999-999999999999")
		request(socks, false)
		stop()
	}
	// The SS endpoint still serves real traffic with its original method/key/port.
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ssSocks := l.Addr().String()
	ssPort := l.Addr().(*net.TCPAddr).Port
	l.Close()
	ssClient, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": ssPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": "9.9.9.9", "port": 24000, "method": glivela.SS2022Method, "password": "AAECAwQFBgcICQoLDA0ODw=="}}}}}})
	_, stopSSClient := start("ss-client", ssClient)
	defer stopSSClient()
	wait443(t, ctx, "127.0.0.1", ssPort)
	request(ssSocks, true)
	if ss.Process.Pid != ssPID {
		t.Fatal("SS listener was replaced")
	}
	// Replaying an identical real counter sample must not double-bill it.
	sample := counter()
	beforeReplay := s.business.material.TrafficCounters[user.Credential.ID]
	if _, e = s.Exchange(ctx, cert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: desired.Revision, ConfigSHA256: desired.ConfigSHA256, RuntimeReady: true}, Traffic: sample}); e != nil {
		t.Fatal(e)
	}
	if s.business.material.TrafficCounters[user.Credential.ID] != beforeReplay {
		t.Fatal("counter replay billed twice")
	}
	stopServer()
	dual.Store(false)
	resource.SecondaryAddress = ""
	resource.Revision++
	resource.AppliedRevision = resource.Revision
	raw, _ = json.Marshal(resource)
	reverted, e := s.ChangePublicIngress(ctx, PublicIngressChange{EntryID: endpoint.Reality.EntryID, Action: "revert", ExpectedRevision: view.Revision, Resource: raw})
	if e != nil || reverted.Port != 24443 {
		t.Fatal("forward recovery", e)
	}
	desired = s.nodes[cert].Desired.clone()
	_, stopRestored := start("entry-restored", desired.Config)
	defer stopRestored()
	wait443(t, ctx, endpoint.Reality.ListenAddress, 24443)
	socks, stop := clientFor(endpoint.Reality.ListenAddress, 24443, user.ProtocolID)
	request(socks, true)
	stop()
	request(ssSocks, true)
	after := s.business.material
	if !reflect.DeepEqual(before.ProtocolSecrets, after.ProtocolSecrets) || !reflect.DeepEqual(before.SubscriptionTokens, after.SubscriptionTokens) {
		t.Fatal("retained credentials or tokens changed")
	}
	for i, account := range before.Plan.Accounts {
		if !reflect.DeepEqual(account.Account, after.Plan.Accounts[i].Account) || !reflect.DeepEqual(account.Credentials, after.Plan.Accounts[i].Credentials) || !reflect.DeepEqual(account.Grants, after.Plan.Accounts[i].Grants) {
			t.Fatal("account plan or authorization changed")
		}
	}
	for id, old := range before.TrafficCounters {
		now := s.business.material.TrafficCounters[id]
		if now.UploadBytes < old.UploadBytes || now.DownloadBytes < old.DownloadBytes {
			t.Fatal("historical usage regressed")
		}
	}
	t.Log("PASS production startup warmup; formal VLESS/Mihomo subscriptions; managed443; real IPv6/IPv4 REALITY; ordinary TLS1.3/H2 fallback; content refresh; denied credential; shared user stats/replay; SS24000; forward recovery")
}
func wait443(t *testing.T, ctx context.Context, address string, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(address, fmt.Sprint(port)))
		if e == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated listener unavailable", address, port)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func public443Origin(t *testing.T, address string) *httptest.Server {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-origin"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP(address)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if e != nil {
		t.Fatal(e)
	}
	key, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ip=8.8.4.4\n") }))
	server.Listener.Close()
	server.Listener, e = net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if e != nil {
		t.Fatal(e)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	return server
}
