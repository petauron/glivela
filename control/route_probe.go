package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
)

// RouteProbe is an entry-side check of one exact migration/configuration.
// The controlled HTTPS target must return its observed source IP as plain text.
// It is not a command execution request or an arbitrary HTTP forwarding API.
type RouteProbe struct {
	AttemptID    string `json:"attemptId"`
	SnapshotID   string `json:"snapshotId"`
	EntryID      string `json:"entryId"`
	LandingID    string `json:"landingId"`
	Revision     uint64 `json:"revision"`
	ConfigSHA256 string `json:"configSha256"`
	SOCKSAddress string `json:"socksAddress"`
	Target       string `json:"target"`
	ExpectedExit string `json:"expectedExit"`
}

type RouteProbeResult struct {
	AttemptID      string    `json:"attemptId"`
	SnapshotID     string    `json:"snapshotId"`
	EntryID        string    `json:"entryId"`
	LandingID      string    `json:"landingId"`
	Revision       uint64    `json:"revision"`
	ConfigSHA256   string    `json:"configSha256"`
	CheckedAt      time.Time `json:"checkedAt"`
	DurationMillis int64     `json:"durationMillis"`
	TLSVerified    bool      `json:"tlsVerified"`
	HTTPStatus     int       `json:"httpStatus,omitempty"`
	ObservedExit   string    `json:"observedExit,omitempty"`
	Passed         bool      `json:"passed"`
	Failure        string    `json:"failure,omitempty"`
}

func (p RouteProbe) Validate() error {
	if !glivela.ValidIdentifier(p.AttemptID) || !glivela.ValidIdentifier(p.SnapshotID) || !glivela.ValidIdentifier(p.EntryID) || !glivela.ValidIdentifier(p.LandingID) || p.Revision == 0 || !glivela.ValidIdentity(p.ConfigSHA256) {
		return errors.New("control: route check identity required")
	}
	proxy, err := netip.ParseAddrPort(p.SOCKSAddress)
	if err != nil || proxy.Port() == 0 || !(proxy.Addr().IsPrivate() || proxy.Addr().IsLoopback() || netip.MustParsePrefix("100.64.0.0/10").Contains(proxy.Addr())) {
		return errors.New("control: route check requires private SOCKS endpoint")
	}
	target, err := url.Parse(p.Target)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil || target.Fragment != "" || target.RawQuery != "" {
		return errors.New("control: controlled HTTPS target required")
	}
	exit, err := netip.ParseAddr(p.ExpectedExit)
	if err != nil || !exit.IsGlobalUnicast() || exit.IsPrivate() || exit.IsLoopback() {
		return errors.New("control: expected public exit required")
	}
	return nil
}

// CheckRoute must run on the enrolled entry, not on the controller or landing.
// A result still needs authenticated origin and current-revision verification
// when accepted by the controller; JSON alone never grants healthy status.
func CheckRoute(ctx context.Context, p RouteProbe) (RouteProbeResult, error) {
	return checkRoute(ctx, p, nil)
}

func checkRoute(ctx context.Context, p RouteProbe, roots *x509.CertPool) (result RouteProbeResult, err error) {
	if err := p.Validate(); err != nil {
		return result, err
	}
	start := time.Now()
	result = RouteProbeResult{AttemptID: p.AttemptID, SnapshotID: p.SnapshotID, EntryID: p.EntryID, LandingID: p.LandingID, Revision: p.Revision, ConfigSHA256: p.ConfigSHA256, CheckedAt: start.UTC()}
	defer func() { result.DurationMillis = time.Since(start).Milliseconds() }()
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: p.SOCKSAddress}),
		DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Target, nil)
	if err != nil {
		return result, err
	}
	response, err := client.Do(request)
	if err != nil {
		// An EOF alone does not identify who closed the connection. Preserve a
		// bounded category, not raw error text containing request/host details.
		result.Failure = "connect-or-tls"
		return result, errors.New("control: route connection or TLS failed")
	}
	defer response.Body.Close()
	result.TLSVerified = response.TLS != nil && len(response.TLS.VerifiedChains) != 0
	result.HTTPStatus = response.StatusCode
	if !result.TLSVerified || response.StatusCode != http.StatusOK {
		result.Failure = "http-status"
		return result, errors.New("control: controlled target did not confirm exit")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65))
	if err != nil || len(raw) > 64 {
		result.Failure = "exit-response"
		return result, errors.New("control: invalid exit response")
	}
	exit, err := netip.ParseAddr(strings.TrimSpace(string(raw)))
	if err != nil {
		result.Failure = "exit-response"
		return result, errors.New("control: invalid exit response")
	}
	result.ObservedExit = exit.String()
	if exit != netip.MustParseAddr(p.ExpectedExit) {
		result.Failure = "exit-mismatch"
		return result, errors.New("control: route used another exit")
	}
	result.Passed = true
	return result, nil
}
