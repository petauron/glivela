// Package landing is Glivela's native landing policy and configuration layer.
// Neither its plan nor its firewall semantics are host application concepts.
package landing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	glivela "github.com/petauron/glivela"
)

type Source struct {
	Address string `json:"address"`
	TCPOnly bool   `json:"tcpOnly"`
}

// Plan keeps the original exact-source private SOCKS trust boundary. Egress
// is a locally assigned source address (including an IPv4 NAT interface), not
// the external address seen by a website. No automatic source selection is
// performed while migrating an existing landing.
type Plan struct {
	Revision uint64   `json:"revision"`
	Address  string   `json:"address"`
	EgressIP string   `json:"egressIp"`
	Sources  []Source `json:"sources"`
}

func tailnetIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.String() == value && netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

func (p Plan) Validate() error {
	if p.Revision == 0 || !tailnetIPv4(p.Address) || !ValidEgressIP(p.EgressIP) || len(p.Sources) > 128 {
		return errors.New("landing: invalid plan")
	}
	egress, _ := netip.ParseAddr(p.EgressIP)
	seen := map[string]bool{}
	for _, source := range p.Sources {
		if !tailnetIPv4(source.Address) || source.Address == p.Address || seen[source.Address] || egress.Is6() && !source.TCPOnly {
			return errors.New("landing: invalid source grant")
		}
		seen[source.Address] = true
	}
	return nil
}

const managementPorts = "22,23,135,139,445,1080,1433,1521,2053,2375,2376,3306,3389,5432,5900,6379,6443,8006,9000,9090,9100,10000"

// Render targets official Xray 26.7.28. It deliberately does not rely on later
// Freedom finalRules semantics. UID-scoped kernel filtering is mandatory for
// post-resolution destination restrictions and address-family enforcement.
func (p Plan) Render() ([]byte, error) {
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
	rules := []any{
		map[string]any{"type": "field", "ip": []string{opposite}, "outboundTag": "deny"},
		map[string]any{"type": "field", "ip": blocked, "outboundTag": "deny"},
		map[string]any{"type": "field", "port": managementPorts, "outboundTag": "deny"},
	}
	sources := slices.Clone(p.Sources)
	slices.SortFunc(sources, func(a, b Source) int { return strings.Compare(a.Address, b.Address) })
	udp := false
	for _, source := range sources {
		network := "tcp"
		if !source.TCPOnly {
			network = "tcp,udp"
			udp = true
		}
		rules = append(rules, map[string]any{"type": "field", "source": []string{source.Address + "/32"}, "network": network, "outboundTag": "egress"})
	}
	value := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"dns":      map[string]any{"servers": []string{"1.1.1.1", "1.0.0.1"}, "queryStrategy": strategy},
		"inbounds": []any{map[string]any{"tag": "landing", "listen": p.Address, "port": SOCKSPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": udp, "ip": p.Address}}},
		// A miss is blocked, including an unrecognized source or UDP grant.
		"outbounds": []any{map[string]any{"tag": "deny", "protocol": "blackhole"}, map[string]any{"tag": "egress", "protocol": "freedom", "sendThrough": p.EgressIP, "settings": map[string]any{"domainStrategy": strategy}}},
		"routing":   map[string]any{"domainStrategy": "IPOnDemand", "rules": rules},
		"policy":    map[string]any{"levels": map[string]any{"0": map[string]any{"handshake": 10, "connIdle": 300}}},
	}
	return json.Marshal(value)
}

func (p Plan) Artifact() (glivela.DesiredArtifact, error) {
	raw, err := p.Render()
	if err != nil {
		return glivela.DesiredArtifact{}, err
	}
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
	result := ServerFirewall{Revision: p.Revision, Address: p.Address, EgressIP: p.EgressIP, UID: uid, Interface: iface}
	for _, source := range p.Sources {
		result.Sources = append(result.Sources, source.Address)
		if source.TCPOnly {
			result.TCPOnlySources = append(result.TCPOnlySources, source.Address)
		}
	}
	return result, result.validate()
}
