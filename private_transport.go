package glivela

import (
	"encoding/base64"
	"errors"
	"net/netip"
)

const SS2022Method = "2022-blake3-aes-128-gcm"

// PrivateTransport belongs to the server entry-to-landing connection; never
// serialize this policy into a public subscription or diagnostic output. An
// explicitly shared listener can use an already-issued client key, without
// exposing any retained server-only key. Empty values read retained SOCKS policy.
type PrivateTransport struct {
	// Port is explicit only for the shared public SS2022 listener. Zero reads
	// retained server policies at their original port; it is not dial fallback.
	ClientListenerID string `json:"clientListenerId,omitempty"`
	Port             int    `json:"port,omitempty"`
	Protocol         string `json:"protocol,omitempty"`
	Key              string `json:"key,omitempty"`
	PublicAddress    string `json:"publicAddress,omitempty"`
}

func (t PrivateTransport) Validate() error {
	if t.Protocol == "" && t.Key == "" && t.PublicAddress == "" && t.Port == 0 && t.ClientListenerID == "" {
		return nil
	}
	key, err := base64.StdEncoding.Strict().DecodeString(t.Key)
	bound := t.ClientListenerID != ""
	public := PublicTransportIPv4(t.PublicAddress) || bound && PublicTransportIPv6(t.PublicAddress)
	validKey := len(key) == 16 || bound && len(key) == 32
	validPort := t.Port == 0 || t.Port == 24000 || bound && t.Port >= 24000 && t.Port <= 24999
	if bound && (!ValidIdentifier(t.ClientListenerID) || t.Port == 0 || !public) || !validPort || t.Port != 0 && t.PublicAddress == "" || t.Protocol != "ss2022" || err != nil || !validKey || base64.StdEncoding.EncodeToString(key) != t.Key || t.PublicAddress != "" && !public {
		return errors.New("glivela: invalid private transport")
	}
	return nil
}

// PublicTransportIPv4 permits a single canonical unicast endpoint, never a
// subnet, wildcard, private management address or DNS-dependent destination.
func PublicTransportIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.Is4() || ip.String() != value || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

// PublicTransportIPv6 accepts only a canonical, non-transition global unicast
// address. Transport endpoints and authorized sources are exact addresses,
// never prefixes or names resolved by a different network namespace.
func PublicTransportIPv6(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Is6() && ip.String() == value && CompositePublicIP(ip)
}

// Method reuses the cipher implied by the issued listener's canonical key.
func (t PrivateTransport) Method() string {
	key, _ := base64.StdEncoding.DecodeString(t.Key)
	if t.ClientListenerID != "" && len(key) == 32 {
		return IPv4ClientSS2022Method
	}
	return SS2022Method
}

func (t PrivateTransport) ListenerPort() int {
	if t.Port != 0 {
		return t.Port
	}
	return DefaultLandingSOCKSPort
}

func (t PrivateTransport) Endpoint(privateAddress string) string {
	if t.PublicAddress != "" {
		return t.PublicAddress
	}
	return privateAddress
}

func (p RoutePeer) outbound(tag string) map[string]any {
	server := map[string]any{"address": p.Transport.Endpoint(p.Address), "port": p.Port}
	protocol := "socks"
	if p.Transport.Protocol == "ss2022" {
		protocol = "shadowsocks"
		server["method"], server["password"] = p.Transport.Method(), p.Transport.Key
	}
	return map[string]any{"protocol": protocol, "tag": tag, "settings": map[string]any{"servers": []any{server}}}
}

// DialTransport is the only socket opened by the entry. The final SS2022
// connection is carried inside the separately authorized intermediate hop.
func (p RoutePeer) DialTransport() PrivateTransport {
	if p.Relay == nil {
		return p.Transport
	}
	r := p.Relay
	address := r.ServerIPv6
	if r.Transport == IPv4RelaySS2022 {
		address = r.ServerIPv4
	}
	return PrivateTransport{Protocol: "ss2022", Key: r.Key, PublicAddress: address, Port: r.Port, ClientListenerID: p.ClientChainID}
}

func (r ClientChainRelay) ValidateServerRelay(final PrivateTransport) error {
	key, err := base64.StdEncoding.Strict().DecodeString(r.Key)
	ipv6 := r.Transport == "" && r.SourceIPv4 == "" && r.ServerIPv4 == "" && PublicTransportIPv6(r.SourceIPv6) && PublicTransportIPv6(r.ServerIPv6) && r.SourceIPv6 != r.ServerIPv6 && r.ServerIPv6 != final.PublicAddress && len(key) == 16
	ipv4 := r.Transport == IPv4RelaySS2022 && r.SourceIPv6 == "" && r.ServerIPv6 == "" && PublicTransportIPv4(r.SourceIPv4) && PublicTransportIPv4(r.ServerIPv4) && r.SourceIPv4 != r.ServerIPv4 && len(key) == 32
	if err != nil || !ValidIdentifier(r.NodeID) || !ValidIdentity(r.CertificateID) || r.Port < 24000 || r.Port > 24999 || (!ipv6 && !ipv4) || !PublicTransportIPv6(final.PublicAddress) || final.Protocol != "ss2022" || final.ClientListenerID == "" {
		return errors.New("glivela: invalid server relay")
	}
	return nil
}

// ServerOutbounds retains both independent issued credentials and chains the
// final proxy through the relay. Neither outbound has a direct fallback.
func (p RoutePeer) ServerOutbounds(tag string) []any {
	final := p.outbound(tag)
	if p.Relay == nil {
		return []any{final}
	}
	relayTag := tag + "-relay"
	final["streamSettings"] = map[string]any{"sockopt": map[string]any{"dialerProxy": relayTag}}
	relay := RoutePeer{Transport: p.DialTransport(), Port: p.Relay.Port}
	return []any{final, relay.outbound(relayTag)}
}
