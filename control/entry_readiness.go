package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/petauron/glivela"
)

// Readiness is deliberately memory-only and bound to an exact worker generation
// and configuration. A new process (including Agent restart) must prove itself.
type entryReadiness struct {
	mu       sync.Mutex
	accepted string
}

func (r *entryReadiness) reset() { r.mu.Lock(); defer r.mu.Unlock(); r.accepted = "" }

func (r *entryReadiness) check(ctx context.Context, identity func() (string, error), probe func(context.Context) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := identity()
	if err != nil || before == "" {
		r.accepted = ""
		return errors.New("control: readiness process unavailable")
	}
	if r.accepted == before {
		return nil
	}
	r.accepted = ""
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if err := probe(ctx); err != nil {
		return err
	}
	after, err := identity()
	if err != nil || after != before || ctx.Err() != nil {
		return errors.New("control: entry changed during readiness probe")
	}
	r.accepted = before
	return nil
}

// Probe every published REALITY SNI using an enabled native business identity.
// Fixed-route readiness is checked once during activation. No
// enabled native identity means no native subscription can be published yet.
func probeEntryReadiness(ctx context.Context, binary, digest string, plan glivela.XrayPlan, localListener bool) error {
	if err := verifyExecutableFile(binary, digest); err != nil {
		return err
	}
	for _, endpoint := range plan.RealityEndpoints {
		var material *glivela.CredentialMaterial
		for i := range plan.Credentials {
			c := &plan.Credentials[i]
			if c.Credential.Enabled && c.Credential.Kind == glivela.NativeCredential && c.Credential.EntryID == endpoint.EntryID {
				material = c
				break
			}
		}
		if material == nil {
			continue
		}
		for _, sni := range endpoint.ServerNames {
			if err := probeRealityClient(ctx, binary, endpoint, *material, sni, "https://www.cloudflare.com/cdn-cgi/trace", nil, localListener && net.ParseIP(endpoint.ListenAddress).To4() != nil, plan.NativeEgress); err != nil {
				return err
			}
		}
	}
	return nil
}

// Uses the installed verified Xray, never downloads a different core. Secrets
// travel on stdin; only loopback is exposed. The caller selects the listener
// after verifying its runtime ownership; REALITY, SNI and target TLS stay checked.
func probeRealityClient(parent context.Context, binary string, endpoint glivela.RealityEndpoint, material glivela.CredentialMaterial, sni, target string, roots *x509.CertPool, proxyProtocol bool, policy glivela.EgressPolicy) error {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("control: readiness client listener unavailable")
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	username, password := rand.Text(), rand.Text()
	fp := endpoint.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	config := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": username, "pass": password}}, "udp": false}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": endpoint.AdvertiseHost, "port": endpoint.AdvertisePort, "users": []any{map[string]any{"id": material.ProtocolID, "encryption": "none", "flow": "xtls-rprx-vision"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": sni, "fingerprint": fp, "password": endpoint.PublicKey, "shortId": endpoint.ShortIDs[0]}}}},
	}
	if proxyProtocol {
		// The owned IPv4 backend requires PROXY v2 just like its published
		// frontend. Use the bundled core's transport dialer instead of a relay.
		outbounds := config["outbounds"].([]any)
		outbounds[0].(map[string]any)["streamSettings"].(map[string]any)["sockopt"] = map[string]any{"dialerProxy": "readiness-listener"}
		config["outbounds"] = append(outbounds, map[string]any{"tag": "readiness-listener", "protocol": "freedom", "settings": map[string]any{"proxyProtocol": 2, "finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{endpoint.AdvertiseHost + "/32"}, "port": strconv.Itoa(endpoint.AdvertisePort)}}}})
	}

	raw, err := json.Marshal(config)
	if err != nil {
		return errors.New("control: readiness client configuration invalid")
	}
	cmd := exec.CommandContext(ctx, binary, "run", "-c", "stdin:")
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return errors.New("control: readiness client failed to start")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { cancel(); <-done }()
	for verifyReadinessListener(cmd.Process.Pid, port) != nil {
		select {
		case <-ctx.Done():
			return errors.New("control: readiness client not listening")
		case <-time.After(50 * time.Millisecond):
		}
	}

	// The entire operation is bounded, including SOCKS and inner TLS. The first
	// request may spend >5s in REALITY initialization; do not use the ordinary
	// landing monitor's shorter handshake timeout here.
	for i := 0; i < 2; i++ {
		budget := 12 * time.Second
		if i == 1 {
			budget = 4 * time.Second
		}
		if err := readinessHTTPS(ctx, address, username, password, target, roots, budget, policy); err != nil {
			return fmt.Errorf("control: REALITY readiness request %d failed", i+1)
		}
	}
	return verifyReadinessListener(cmd.Process.Pid, port)
}

func readinessHTTPS(parent context.Context, address, username, password, target string, roots *x509.CertPool, budget time.Duration, policy glivela.EgressPolicy) error {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	// Retry listener startup only. A completed business failure is not hidden.
	for {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: address, User: url.UserPassword(username, password)}),
		DialContext:     (&net.Dialer{Timeout: budget}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: budget, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: budget, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 || response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return errors.New("control: invalid readiness HTTPS response")
	}
	// Cloudflare's trace is independently TLS-authenticated. Require a public
	// observed exit rather than accepting an arbitrary HTML success page.
	for _, line := range bytes.Split(body, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("ip=")) {
			ip := net.ParseIP(string(bytes.TrimPrefix(line, []byte("ip="))))
			if ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				if policy == glivela.EgressIPv4Only && ip.To4() == nil || policy == glivela.EgressIPv6Only && ip.To4() != nil {
					return errors.New("control: readiness exit does not match native egress family")
				}
				return nil
			}
		}
	}
	return errors.New("control: readiness response has no public exit")
}

func readinessGeneration(pid int, started, sha string) string {
	return strconv.Itoa(pid) + ":" + started + ":" + sha
}
