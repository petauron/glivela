package glivela

import (
	"encoding/base64"
	"errors"
	"net/netip"
)

const SS2022Method = "2022-blake3-aes-128-gcm"

// PrivateTransport belongs only to the entry-to-landing connection. Its key
// must never be included in public subscriptions or diagnostic output. Empty
// values describe the retained pre-migration SOCKS configuration, not fallback.
type PrivateTransport struct {
	Protocol      string `json:"protocol,omitempty"`
	Key           string `json:"key,omitempty"`
	PublicAddress string `json:"publicAddress,omitempty"`
}

func (t PrivateTransport) Validate() error {
	if t.Protocol == "" && t.Key == "" && t.PublicAddress == "" {
		return nil
	}
	key, err := base64.StdEncoding.Strict().DecodeString(t.Key)
	if t.Protocol != "ss2022" || err != nil || len(key) != 16 || base64.StdEncoding.EncodeToString(key) != t.Key || t.PublicAddress != "" && !PublicTransportIPv4(t.PublicAddress) {
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
		server["method"], server["password"] = SS2022Method, p.Transport.Key
	}
	return map[string]any{"protocol": protocol, "tag": tag, "settings": map[string]any{"servers": []any{server}}}
}
