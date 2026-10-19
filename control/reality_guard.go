package control

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/petauron/glivela/landing"
)

// The MVP retains previously reviewed targets, rather than selecting new
// CDN/WAF targets or trusting system DNS to choose a different fallback.
// Verify the exact configured public IP with every retained SNI before changing
// a working runtime. No proxy environment or disabled certificate validation.
func verifyEntryRealityTargets(ctx context.Context, desired Desired) error {
	if desired.Entry == nil {
		return errors.New("control: entry target inventory required")
	}
	check, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, endpoint := range desired.Entry.RealityEndpoints {
		host, port, err := net.SplitHostPort(endpoint.Target)
		address, addressErr := netip.ParseAddr(host)
		if err != nil || addressErr != nil || !landing.PublicIP(address) || port != "443" || address.Zone() != "" {
			return errors.New("control: reviewed pinned public REALITY target required")
		}
		for _, name := range endpoint.ServerNames {
			dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{
				MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: name,
				NextProtos: []string{"h2"}, CurvePreferences: []tls.CurveID{tls.X25519},
			}}
			connection, err := dialer.DialContext(check, "tcp", endpoint.Target)
			if err != nil {
				return errors.New("control: REALITY target TLS validation failed; retain existing runtime")
			}
			verified, ok := connection.(*tls.Conn)
			if !ok {
				connection.Close()
				return errors.New("control: REALITY target did not establish TLS")
			}
			state := verified.ConnectionState()
			connection.Close()
			if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || state.PeerCertificates[0].VerifyHostname(name) != nil {
				return errors.New("control: REALITY target must retain valid TLS13/X25519/h2/SNI")
			}
		}
	}
	return nil
}
