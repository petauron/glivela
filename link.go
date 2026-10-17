package glivela

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

type ProtocolKind string

const (
	VLESSReality ProtocolKind = "vless-reality"
	Hysteria2    ProtocolKind = "hysteria2"
)

func (p ProtocolKind) Valid() bool { return p == VLESSReality || p == Hysteria2 }

func parseVLESSLink(raw string) (*url.URL, error) {
	link, err := url.Parse(raw)
	if err != nil || link.Scheme != "vless" || link.User == nil || link.User.Username() == "" || link.Hostname() == "" || link.Port() == "" || link.Query().Get("security") != "reality" || link.Path != "" {
		return nil, errors.New("glivela: a managed VLESS REALITY link is required")
	}
	if _, password := link.User.Password(); password {
		return nil, errors.New("glivela: invalid VLESS identity")
	}
	return link, nil
}

func parseHysteria2Link(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "hysteria2" && parsed.Scheme != "hy2" || parsed.User == nil || parsed.User.Username() == "" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Query().Get("sni") == "" || parsed.Query().Get("alpn") != "h3" || parsed.Query().Has("insecure") {
		return nil, errors.New("glivela: a managed Hysteria2 link is required")
	}
	if _, password := parsed.User.Password(); password {
		return nil, errors.New("glivela: invalid Hysteria2 identity")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || !validPort(port) {
		return nil, errors.New("glivela: invalid Hysteria2 port")
	}
	parsed.Scheme = "hysteria2"
	return parsed, nil
}

func parseProtocolLink(raw string, protocol ProtocolKind) (*url.URL, error) {
	switch protocol {
	case VLESSReality:
		return parseVLESSLink(raw)
	case Hysteria2:
		return parseHysteria2Link(raw)
	default:
		return nil, errors.New("glivela: unsupported subscription protocol")
	}
}

func protocolLinkIdentity(link *url.URL, protocol ProtocolKind) string {
	if link == nil || link.User == nil || !protocol.Valid() {
		return ""
	}
	return Identity(link.User.Username())
}

func sameLinkIdentity(left, right string) bool {
	a, err := parseVLESSLink(left)
	if err != nil {
		return false
	}
	b, err := parseVLESSLink(right)
	return err == nil && a.Host == b.Host && a.User.Username() == b.User.Username() && sameRealityTransport(a, b)
}

func sameProtocolLinkIdentity(left, right string, protocol ProtocolKind) bool {
	a, err := parseProtocolLink(left, protocol)
	if err != nil {
		return false
	}
	b, err := parseProtocolLink(right, protocol)
	if err != nil || a.User.Username() != b.User.Username() {
		return false
	}
	return sameProtocolTransport(a, b, protocol)
}

func sameProtocolTransport(a, b *url.URL, protocol ProtocolKind) bool {
	if a == nil || b == nil || a.Host != b.Host {
		return false
	}
	if protocol == VLESSReality {
		return sameRealityTransport(a, b)
	}
	return a.Query().Get("sni") == b.Query().Get("sni") && a.Query().Get("alpn") == b.Query().Get("alpn")
}

func sameRealityTransport(left, right *url.URL) bool {
	for _, key := range []string{"security", "type", "sni", "pbk", "sid", "fp", "flow"} {
		if left.Query().Get(key) != right.Query().Get(key) {
			return false
		}
	}
	return true
}

func sameMihomoRealityTransport(proxy map[string]any, link *url.URL) bool {
	query := link.Query()
	reality, _ := proxy["reality-opts"].(map[string]any)
	return proxy["network"] == query.Get("type") && proxy["servername"] == query.Get("sni") &&
		proxy["flow"] == query.Get("flow") && reality["public-key"] == query.Get("pbk") &&
		strings.TrimSpace(query.Get("sid")) == strings.TrimSpace(stringValue(reality["short-id"]))
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
