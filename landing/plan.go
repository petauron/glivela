// Package landing is Glivela's native landing policy and configuration layer.
// Neither its plan nor its firewall semantics are host application concepts.
package landing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	glivela "github.com/petauron/glivela"
)

type Source struct {
	Address       string `json:"address"`
	TCPOnly       bool   `json:"tcpOnly"`
	PublicAddress string `json:"publicAddress,omitempty"`
}

// Plan keeps the original exact-source private SOCKS trust boundary. Egress
// is a locally assigned source address (including an IPv4 NAT interface), not
// the external address seen by a website. No automatic source selection is
// performed while migrating an existing landing.
type ClientListener struct {
	Shared    bool   `json:"shared,omitempty"`
	Transport string `json:"transport,omitempty"`
	Address   string `json:"address,omitempty"`
	ID        string `json:"id"`
	Port      int    `json:"port"`
	Key       string `json:"key"`
	Source    string `json:"source"`
}

type Plan struct {
	// Explicit client-only IPv6 bind; retained IPv4 grants are inactive.
	IPv6OnlyAddress string                   `json:"ipv6OnlyAddress,omitempty"`
	PublicSSH       *glivela.PublicSSHPolicy `json:"publicSSH,omitempty"`
	ClientListeners []ClientListener         `json:"clientListeners,omitempty"`
	Transport       glivela.PrivateTransport `json:"transport,omitzero"`
	Revision        uint64                   `json:"revision"`
	Address         string                   `json:"address"`
	EgressIP        string                   `json:"egressIp"`
	Sources         []Source                 `json:"sources"`
}

func tailnetIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.String() == value && netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

func (p Plan) Validate() error {
	if err := p.PublicSSH.Validate(); err != nil {
		return err
	}
	for _, address := range []string{p.EgressIP, p.Transport.PublicAddress} {
		if err := p.PublicSSH.RequireHost(address); err != nil {
			return err
		}
	}
	if p.Revision == 0 || !tailnetIPv4(p.Address) || !ValidEgressIP(p.EgressIP) || len(p.Sources) > 128 || len(p.ClientListeners) > 1000 || p.Transport.Validate() != nil {
		return errors.New("landing: invalid plan")
	}
	egress, _ := netip.ParseAddr(p.EgressIP)
	if p.IPv6OnlyAddress != "" && (!glivela.PublicTransportIPv6(p.IPv6OnlyAddress) || !egress.Is6() || p.PublicSSH.RequireHost(p.IPv6OnlyAddress) != nil) {
		return errors.New("landing: exact IPv6 listener and fixed IPv6 egress required")
	}
	seen := map[string]bool{}
	publicSources := map[string]bool{}
	for _, source := range p.Sources {
		if !tailnetIPv4(source.Address) || source.Address == p.Address || seen[source.Address] || egress.Is6() && !source.TCPOnly {
			return errors.New("landing: invalid source grant")
		}
		seen[source.Address] = true
		if p.Transport.PublicAddress != "" {
			if !glivela.PublicTransportIPv4(source.PublicAddress) || source.PublicAddress == p.Transport.PublicAddress || publicSources[source.PublicAddress] {
				return errors.New("landing: exact unique public source required")
			}
			publicSources[source.PublicAddress] = true
		} else if source.PublicAddress != "" {
			return errors.New("landing: public source without public transport")
		}
	}
	seenPorts := map[int]ClientListener{}
	seenIDs := map[string]bool{}
	for _, c := range p.ClientListeners {
		if c.Transport == "ipv6-ss2022" {
			if p.IPv6OnlyAddress != "" && c.Address != p.IPv6OnlyAddress {
				return errors.New("landing: client listener differs from explicit IPv6 bind")
			}
			if err := p.PublicSSH.RequireHost(c.Address); err != nil {
				return err
			}
		}
		key, err := base64.StdEncoding.DecodeString(c.Key)
		validTransport := (c.Transport == "" || c.Transport == glivela.IPv4ClientSS2022) && c.Address == "" && publicSources[c.Source] && (len(key) == 32 && !c.Shared || len(key) == 16 && c.Shared && c.Transport == glivela.IPv4ClientSS2022) && (c.Transport == "" || base64.StdEncoding.EncodeToString(key) == c.Key) ||
			c.Transport == glivela.IPv4RelaySS2022 && c.Address == "" && !c.Shared && glivela.PublicTransportIPv4(c.Source) && c.Source != p.Transport.PublicAddress && len(key) == 32 && base64.StdEncoding.EncodeToString(key) == c.Key ||
			c.Transport == "ipv6-ss2022" && glivela.PublicTransportIPv6(c.Address) && glivela.PublicTransportIPv6(c.Source) && c.Address != c.Source && len(key) == 16 && base64.StdEncoding.EncodeToString(key) == c.Key
		previous, duplicate := seenPorts[c.Port]
		if p.Transport.PublicAddress == "" && (p.IPv6OnlyAddress == "" || c.Transport != "ipv6-ss2022") || !glivela.ValidIdentifier(c.ID) || seenIDs[c.ID] || c.Port < 24000 || c.Port > 24999 || duplicate && (!previous.Shared || !c.Shared || previous.Key != c.Key) || c.Shared && c.Port != 24000 || err != nil || !validTransport {
			return errors.New("landing: invalid client listener")
		}
		seenPorts[c.Port] = c
		seenIDs[c.ID] = true
	}
	return nil
}

// Exact historical rule shape, only for snapshot verification and owned cleanup.
const legacyManagementPorts = "22,23,135,139,445,1080,1433,1521,2053,2375,2376,3306,3389,5432,5900,6379,6443,8006,9000,9090,9100,10000"

// Render targets official Xray 26.10.31. SOCKS does not receive the core's
// default VLESS/Hysteria private-target guard. UID-scoped kernel filtering
// remains mandatory for post-resolution targets and address-family limits.
const RenderVersion uint8 = 4

func (p Plan) Render() ([]byte, error) {
	return p.RenderVersion(RenderVersion)
}

// RenderVersion reads old signed artifacts without changing their hash.
func (p Plan) RenderVersion(version uint8) ([]byte, error) {
	if version > RenderVersion || p.IPv6OnlyAddress != "" && version < 3 || version < 4 && slices.ContainsFunc(p.ClientListeners, func(c ClientListener) bool { return c.Transport == glivela.IPv4RelaySS2022 }) {
		return nil, errors.New("landing: unsupported render version")
	}
	if version >= 1 {
		p.PublicSSH = nil
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	egress, _ := netip.ParseAddr(p.EgressIP)
	strategy, opposite := "UseIPv4", "::/0"
	if egress.Is6() {
		strategy, opposite = "UseIPv6", "0.0.0.0/0"
	}
	blocked := append(slices.Clone(blockedIPv4), "::/0")
	if egress.Is6() {
		blocked = append(slices.Clone(blockedIPv4), blockedIPv6...)
		blocked = append(blocked, "::/3", "4000::/2", "8000::/1")
	}
	dnsServers := []string{"1.1.1.1", "1.0.0.1"}
	resolverIPs := []string{"1.1.1.1/32", "1.0.0.1/32"}
	resolverNetwork := "tcp,udp"
	resolverOutbound := map[string]any{"tag": "resolver", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "AsIs"}}
	if version >= 2 && egress.Is6() {
		// Use the existing fixed-source IPv6 TCP policy without depending on
		// IPv4 or authorizing UDP. Literal addresses avoid bootstrap DNS.
		dnsServers = []string{"tcp://[2606:4700:4700::1111]", "tcp://[2606:4700:4700::1001]"}
		resolverIPs = []string{"2606:4700:4700::1111/128", "2606:4700:4700::1001/128"}
		resolverNetwork = "tcp"
		resolverOutbound["sendThrough"] = p.EgressIP
	}
	rules := []any{
		// Built-in DNS has no authorized SOCKS client source. Route only its
		// tagged queries to the exact resolvers before business-family rules.
		map[string]any{"type": "field", "inboundTag": []string{"resolver"}, "ip": resolverIPs, "port": "53", "network": resolverNetwork, "outboundTag": "resolver"},
		map[string]any{"type": "field", "ip": []string{opposite}, "outboundTag": "deny"},
		map[string]any{"type": "field", "ip": blocked, "outboundTag": "deny"},
	}
	if version == 0 {
		rules = append(rules, managementPortRule(p.PublicSSH))
	}
	if version == 0 && p.PublicSSH != nil {
		addresses := slices.Clone(p.PublicSSH.HostPublicAddresses)
		slices.Sort(addresses)
		rules = append(rules,
			map[string]any{"type": "field", "network": "tcp", "port": "22", "ip": addresses, "outboundTag": "deny"},
			map[string]any{"type": "field", "network": "udp", "port": "22", "outboundTag": "deny"})
	}
	sources := slices.Clone(p.Sources)
	slices.SortFunc(sources, func(a, b Source) int { return strings.Compare(a.Address, b.Address) })
	udp := false
	for _, source := range sources {
		if p.IPv6OnlyAddress != "" {
			continue
		}
		network := "tcp"
		if !source.TCPOnly {
			network = "tcp,udp"
			udp = true
		}
		address := source.Address
		if p.Transport.PublicAddress != "" {
			address = source.PublicAddress
		}
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{"landing"}, "source": []string{address + "/32"}, "network": network, "outboundTag": "egress"})
	}
	inbound := map[string]any{"tag": "landing", "listen": p.Address, "port": SOCKSPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": udp, "ip": p.Address}}
	if p.Transport.Protocol == "ss2022" {
		inbound["listen"] = p.Transport.Endpoint(p.Address)
		network := "tcp"
		if udp {
			network = "tcp,udp"
		}
		inbound["protocol"] = "shadowsocks"
		inbound["settings"] = map[string]any{"method": glivela.SS2022Method, "password": p.Transport.Key, "network": network}
	}
	inbounds := []any{}
	if p.IPv6OnlyAddress == "" {
		inbounds = append(inbounds, inbound)
	}
	sharedInbounds := map[string]bool{}
	for _, c := range p.ActiveClientListeners() {
		tag := "client-chain-" + c.ID
		address, method, prefix := p.Transport.PublicAddress, "aes-256-gcm", "/32"
		if c.Transport == glivela.IPv4ClientSS2022 || c.Transport == glivela.IPv4RelaySS2022 {
			method = glivela.IPv4ClientSS2022Method
		}
		if c.Transport == "ipv6-ss2022" {
			address, method, prefix = c.Address, glivela.SS2022Method, "/128"
		}
		if c.Shared {
			method = glivela.SS2022Method
			tag = "client-landing-" + address
		}
		if !c.Shared || !sharedInbounds[address] {
			inbounds = append(inbounds, map[string]any{"tag": tag, "listen": address, "port": c.Port, "protocol": "shadowsocks", "settings": map[string]any{"method": method, "password": c.Key, "network": "tcp"}})
			if c.Shared {
				sharedInbounds[address] = true
			}
		}
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{tag}, "source": []string{c.Source + prefix}, "network": "tcp", "outboundTag": "egress"})
	}
	value := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"dns":      map[string]any{"tag": "resolver", "servers": dnsServers, "queryStrategy": strategy},
		"inbounds": inbounds,
		// A miss is blocked, including an unrecognized source or UDP grant.
		"outbounds": []any{map[string]any{"tag": "deny", "protocol": "blackhole"}, map[string]any{"tag": "egress", "protocol": "freedom", "sendThrough": p.EgressIP, "settings": map[string]any{"domainStrategy": strategy}}, resolverOutbound},
		"routing":   map[string]any{"domainStrategy": "IPOnDemand", "rules": rules},
		"policy":    map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 10, "connIdle": 300}}},
	}
	return json.Marshal(value)
}

func (p Plan) Artifact() (glivela.DesiredArtifact, error) {
	return p.ArtifactVersion(RenderVersion)
}

func (p Plan) ArtifactVersion(version uint8) (glivela.DesiredArtifact, error) {
	raw, err := p.RenderVersion(version)
	if err != nil {
		return glivela.DesiredArtifact{}, err
	}
	// Configuration integrity digest, not password storage or key derivation.
	// Client keys are random AEAD keys and remain inside private configuration.
	digest := sha256.Sum256(raw)
	return glivela.DesiredArtifact{Revision: p.Revision, Config: raw, ConfigSHA256: hex.EncodeToString(digest[:])}, nil
}

// Firewall binds the same policy to locally owned execution identities. A
// caller must verify the UID belongs exclusively to the Xray worker, not the
// root controller/node process, and that Address belongs to this interface.
func (p Plan) Firewall(uid uint32, iface string) (ServerFirewall, error) {
	if err := p.Validate(); err != nil {
		return ServerFirewall{}, err
	}
	result := ServerFirewall{PublicSSH: p.PublicSSH.Clone(), Revision: p.Revision, IPv6Only: p.IPv6OnlyAddress != "", Address: p.ListenerAddress(), EgressIP: p.EgressIP, UID: uid, Interface: iface, Public: p.Transport.PublicAddress != "" || p.IPv6OnlyAddress != ""}
	for _, source := range p.Sources {
		if p.IPv6OnlyAddress != "" {
			continue
		}
		address := source.Address
		if result.Public {
			address = source.PublicAddress
		}
		result.Sources = append(result.Sources, address)
		if source.TCPOnly {
			result.TCPOnlySources = append(result.TCPOnlySources, address)
		}
	}
	for _, c := range p.ActiveClientListeners() {
		result.ClientListeners = append(result.ClientListeners, ClientListenerPolicy{Shared: c.Shared, Port: c.Port, Source: c.Source, Transport: c.Transport, Address: c.Address})
	}
	return result, result.validate()
}

// ListenerAddress never guesses a replacement public address.
func (p Plan) ListenerAddress() string {
	if p.IPv6OnlyAddress != "" {
		return p.IPv6OnlyAddress
	}
	return p.Transport.Endpoint(p.Address)
}

// Retain historical IPv4 identities without activating them on IPv6-only hosts.
func (p Plan) ActiveClientListeners() []ClientListener {
	if p.IPv6OnlyAddress == "" {
		return p.ClientListeners
	}
	active := []ClientListener{}
	for _, c := range p.ClientListeners {
		if c.Transport == "ipv6-ss2022" {
			active = append(active, c)
		}
	}
	return active
}
