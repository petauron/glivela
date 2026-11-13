package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	glivela "github.com/petauron/glivela"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"time"
)

// ProbeWithCore uses the installed, digest-verified Xray to implement SS2022,
// not another crypto implementation. A short-lived authenticated loopback
// listener belongs only to this bounded check. It has exactly one encrypted
// outbound, no direct fallback, no environment proxy and no public listener.
func ProbeWithCore(ctx context.Context, p RouteProbe, binary, digest string) (RouteProbeResult, error) {
	return probeWithCore(ctx, p, binary, digest, nil)
}

func probeWithCore(ctx context.Context, p RouteProbe, binary, digest string, roots *x509.CertPool) (RouteProbeResult, error) {
	if p.Transport.Protocol == "" {
		return CheckRoute(ctx, p)
	}
	failed := RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: time.Now().UTC(), Failure: "probe-runtime"}
	if p.Validate() != nil || verifyExecutableFile(binary, digest) != nil {
		return failed, errors.New("control: encrypted probe prerequisites unavailable")
	}
	endpoint, err := netip.ParseAddrPort(p.SOCKSAddress)
	if err != nil || !(p.Transport.PublicAddress != "" && endpoint.Addr().String() == p.Transport.PublicAddress && int(endpoint.Port()) == p.Transport.ListenerPort() || netip.MustParsePrefix("100.64.0.0/10").Contains(endpoint.Addr()) && int(endpoint.Port()) == p.Transport.ListenerPort() || endpoint.Addr().IsLoopback()) {
		return failed, errors.New("control: encrypted probe requires assigned private endpoint")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return failed, errors.New("control: probe listener unavailable")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	address := listener.Addr().String()
	_ = listener.Close()
	var token [24]byte
	if _, err = rand.Read(token[:]); err != nil {
		return failed, errors.New("control: probe identity unavailable")
	}
	password := hex.EncodeToString(token[:])
	config := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": "probe", "pass": password}}, "udp": false}}},
		"outbounds": (glivela.RoutePeer{Address: endpoint.Addr().String(), Transport: p.Transport, Port: int(endpoint.Port()), Relay: p.Relay, ClientChainID: p.Transport.ClientListenerID}).ServerOutbounds("probe-exit"),
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return failed, errors.New("control: probe configuration unavailable")
	}
	child, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, binary, "run", "-config", "stdin:")
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.Env = []string{"GOMAXPROCS=1", "GOMEMLIMIT=24MiB"}
	if cmd.Start() != nil {
		return failed, errors.New("control: probe core unavailable")
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	ready, stop := context.WithTimeout(child, 2*time.Second)
	defer stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, dialErr := (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(ready, "tcp", address)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case <-ready.Done():
			return failed, errors.New("control: probe core listener unavailable")
		case <-ticker.C:
		}
	}
	return checkRouteProxy(child, p, roots, &url.URL{Scheme: "socks5", Host: address, User: url.UserPassword("probe", password)})
}
