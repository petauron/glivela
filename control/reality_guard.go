package control

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/petauron/glivela/landing"
)

// Retain the configured target (including its hostname) and SNI. Validate the
// actual resolved destination before dialing, without persisting a CDN address.
func verifyEntryRealityTargets(ctx context.Context, desired Desired) error {
	if desired.Entry == nil {
		return errors.New("control: entry target inventory required")
	}
	check, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for _, endpoint := range desired.Entry.RealityEndpoints {
		host, port, err := net.SplitHostPort(endpoint.Target)
		if err != nil || host == "" || port != "443" {
			return errors.New("control: public REALITY target on port 443 required")
		}
		for _, name := range endpoint.ServerNames {
			dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second, Control: publicRealityDestination}, Config: &tls.Config{
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

func publicRealityDestination(_, address string, _ syscall.RawConn) error {
	destination, err := netip.ParseAddrPort(address)
	if err != nil || destination.Port() != 443 || destination.Addr().Zone() != "" || !landing.PublicIP(destination.Addr().Unmap()) {
		return errors.New("control: REALITY destination must resolve to a public address")
	}
	return nil
}
