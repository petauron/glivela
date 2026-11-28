package landing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	glivela "github.com/petauron/glivela"
)

// EIHRelayTarget is one exact authorized downstream landing IP:port/TCP target
// permitted on a relay user's dedicated direct freedom outbound finalRules.
type EIHRelayTarget struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

func (t EIHRelayTarget) Validate() error {
	if t.Port != glivela.RelayPoolPort || !(glivela.PublicTransportIPv4(t.Address) || glivela.PublicTransportIPv6(t.Address)) {
		return errors.New("landing: invalid EIH relay destination")
	}
	return nil
}

// EIHUser is one authenticated SS2022 EIH client on a single-port 24000 socket.
// Role "landing" routes to public internet egress (optionally allowing XUDP with
// UDP 443 blocked). Role "relay" routes TCP-only to a dedicated direct freedom
// outbound (without dialerProxy) whose finalRules allow only RelayTargets.
type EIHUser struct {
	ID           string           `json:"id"`
	Email        string           `json:"email"`
	Key          string           `json:"key"`
	Source       string           `json:"source"`
	Role         string           `json:"role"`
	UDP          bool             `json:"udp,omitempty"`
	EgressIP     string           `json:"egressIp,omitempty"`
	RelayTargets []EIHRelayTarget `json:"relayTargets,omitempty"`
}

// EIHListener binds one exact public IPv4 or IPv6 address on port 24000 using
// 2022-blake3-aes-128-gcm multi-user EIH (server-iPSK + per-authorization uPSK).
type EIHListener struct {
	Address   string    `json:"address"`
	Port      int       `json:"port"`
	ServerKey string    `json:"serverKey"`
	Users     []EIHUser `json:"users"`
}

// EIHRelayPolicy authorizes exact relay-only TCP egress in ServerFirewall.
type EIHRelayPolicy struct {
	Source  string `json:"source"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// EIHListenerPolicy binds an EIHListener's exact sources and egress scope to
// kernel nftables without carrying any secrets.
type EIHListenerPolicy struct {
	Interface   string           `json:"interface,omitempty"`
	Address     string           `json:"address"`
	Port        int              `json:"port"`
	Sources     []string         `json:"sources"`
	EgressIPs   []string         `json:"egressIps,omitempty"`
	RelayEgress []EIHRelayPolicy `json:"relayEgress,omitempty"`
}

func eihInboundTag(address string) string {
	family := "v4"
	if strings.Contains(address, ":") {
		family = "v6"
	}
	sum := sha256.Sum256([]byte(address))
	return "eih-" + family + "-" + hex.EncodeToString(sum[:8])
}

func eihRelayOutboundTag(address, userID string) string {
	sum := sha256.Sum256([]byte(address + "\x00" + userID))
	return "eih-relay-" + hex.EncodeToString(sum[:12])
}

func exactHostCIDR(address string) string {
	if strings.Contains(address, ":") {
		return address + "/128"
	}
	return address + "/32"
}

func (p Plan) validateEIHListeners() error {
	if len(p.EIHListeners) > 16 {
		return errors.New("landing: too many EIH listeners")
	}
	seenAddr := map[string]bool{}
	seenUserID := map[string]bool{}
	seenEmail := map[string]bool{}
	totalUsers := 0
	for _, l := range p.EIHListeners {
		isV4 := glivela.PublicTransportIPv4(l.Address)
		isV6 := glivela.PublicTransportIPv6(l.Address)
		if (!isV4 && !isV6) || l.Port != glivela.RelayPoolPort || !glivela.ValidSS2022Key16(l.ServerKey) || seenAddr[l.Address] || len(l.Users) == 0 || len(l.Users) > 1000 {
			return errors.New("landing: invalid EIH listener")
		}
		if p.IPv6OnlyAddress != "" && (!isV6 || l.Address != p.IPv6OnlyAddress) {
			return errors.New("landing: EIH listener differs from explicit IPv6 bind")
		}
		if err := p.PublicSSH.RequireHost(l.Address); err != nil {
			return err
		}
		if p.HasServerListener() && p.Transport.Endpoint(p.Address) == l.Address && p.Transport.ListenerPort() == l.Port {
			return errors.New("landing: EIH listener conflicts with single-user server socket")
		}
		for _, c := range p.ActiveClientListeners() {
			cAddr := p.Transport.PublicAddress
			if c.Transport == "ipv6-ss2022" || c.Interface != "" {
				cAddr = c.Address
			}
			if cAddr == l.Address && c.Port == l.Port {
				return errors.New("landing: EIH listener conflicts with legacy client socket")
			}
		}
		seenAddr[l.Address] = true
		seenKeys := map[string]bool{}
		for _, u := range l.Users {
			totalUsers++
			if totalUsers > 2000 || !glivela.ValidIdentifier(u.ID) || u.Email == "" || len(u.Email) > 256 || strings.TrimSpace(u.Email) != u.Email || strings.ContainsAny(u.Email, "\x00\r\n") || !glivela.ValidSS2022Key16(u.Key) || seenUserID[u.ID] || seenEmail[u.Email] || seenKeys[u.Key] || u.Source == l.Address {
				return errors.New("landing: invalid EIH user")
			}
			if isV4 && !glivela.PublicTransportIPv4(u.Source) || isV6 && !glivela.PublicTransportIPv6(u.Source) {
				return errors.New("landing: EIH user source address family mismatch")
			}
			switch u.Role {
			case "landing":
				if len(u.RelayTargets) != 0 {
					return errors.New("landing: landing EIH user cannot carry relay targets")
				}
				if u.EgressIP != "" && (!ValidEgressIP(u.EgressIP) || p.PublicSSH.RequireHost(u.EgressIP) != nil) {
					return errors.New("landing: invalid landing EIH egress source")
				}
			case "relay":
				if u.UDP || len(u.RelayTargets) == 0 || len(u.RelayTargets) > 256 || !ValidEgressIP(u.EgressIP) || p.PublicSSH.RequireHost(u.EgressIP) != nil {
					return errors.New("landing: invalid relay EIH user")
				}
				egressIP, _ := netip.ParseAddr(u.EgressIP)
				seenTargets := map[string]bool{}
				for _, target := range u.RelayTargets {
					if target.Validate() != nil || target.Address == l.Address || target.Address == u.EgressIP {
						return errors.New("landing: invalid relay EIH target")
					}
					targetIP, _ := netip.ParseAddr(target.Address)
					if targetIP.Is6() != egressIP.Is6() {
						return errors.New("landing: relay target family must match relay egress source")
					}
					key := target.Address + ":" + strconv.Itoa(target.Port)
					if seenTargets[key] {
						return errors.New("landing: duplicate relay EIH target")
					}
					seenTargets[key] = true
				}
			default:
				return errors.New("landing: unsupported EIH user role")
			}
			seenUserID[u.ID], seenEmail[u.Email], seenKeys[u.Key] = true, true, true
		}
	}
	return nil
}

func (p Plan) activeEIHListeners() []EIHListener {
	if len(p.EIHListeners) == 0 {
		return nil
	}
	out := make([]EIHListener, 0, len(p.EIHListeners))
	for _, l := range p.EIHListeners {
		if p.IPv6OnlyAddress != "" && !strings.Contains(l.Address, ":") {
			continue
		}
		out = append(out, l)
	}
	slices.SortFunc(out, func(a, b EIHListener) int { return strings.Compare(a.Address, b.Address) })
	return out
}

func (p Plan) renderEIH(inbounds, outbounds, rules []any, dual bool) ([]any, []any, []any) {
	listeners := p.activeEIHListeners()
	if len(listeners) == 0 {
		return inbounds, outbounds, rules
	}
	for _, l := range listeners {
		tag := eihInboundTag(l.Address)
		users := slices.Clone(l.Users)
		slices.SortFunc(users, func(a, b EIHUser) int { return strings.Compare(a.ID, b.ID) })
		clients := make([]any, 0, len(users))
		for _, u := range users {
			clients = append(clients, map[string]any{
				"email":    u.Email,
				"password": u.Key,
				"level":    0,
			})
		}
		inbounds = append(inbounds, map[string]any{
			"tag":      tag,
			"listen":   l.Address,
			"port":     l.Port,
			"protocol": "shadowsocks",
			"settings": map[string]any{
				"method":   glivela.SS2022Method,
				"password": l.ServerKey,
				"network":  "tcp",
				"clients":  clients,
			},
		})
		for _, u := range users {
			sourceCIDR := exactHostCIDR(u.Source)
			switch u.Role {
			case "landing":
				ip := u.EgressIP
				if ip == "" {
					ip = p.EgressIP
				}
				outbound := "egress"
				if ip != p.EgressIP {
					outbound = clientEgressTag(ip)
				}
				if dual {
					blockedFamily := "::/0"
					if strings.Contains(ip, ":") {
						blockedFamily = "0.0.0.0/0"
					}
					rules = append(rules, map[string]any{
						"type":        "field",
						"inboundTag":  []string{tag},
						"user":        []string{u.Email},
						"source":      []string{sourceCIDR},
						"ip":          []string{blockedFamily},
						"outboundTag": "deny",
					})
				}
				network := "tcp"
				if u.UDP {
					network = "tcp,udp"
					rules = append(rules, map[string]any{
						"type":        "field",
						"inboundTag":  []string{tag},
						"user":        []string{u.Email},
						"source":      []string{sourceCIDR},
						"network":     "udp",
						"port":        "443",
						"outboundTag": "deny",
					})
				}
				rules = append(rules, map[string]any{
					"type":        "field",
					"inboundTag":  []string{tag},
					"user":        []string{u.Email},
					"source":      []string{sourceCIDR},
					"network":     network,
					"outboundTag": outbound,
				})
				rules = append(rules, map[string]any{
					"type":        "field",
					"inboundTag":  []string{tag},
					"user":        []string{u.Email},
					"outboundTag": "deny",
				})
			case "relay":
				relayTag := eihRelayOutboundTag(l.Address, u.ID)
				targets := slices.Clone(u.RelayTargets)
				slices.SortFunc(targets, func(a, b EIHRelayTarget) int {
					if c := strings.Compare(a.Address, b.Address); c != 0 {
						return c
					}
					return a.Port - b.Port
				})
				finalRules := make([]any, 0, len(targets)+1)
				for _, target := range targets {
					finalRules = append(finalRules, map[string]any{
						"action":  "allow",
						"ip":      []string{exactHostCIDR(target.Address)},
						"port":    strconv.Itoa(target.Port),
						"network": "tcp",
					})
				}
				finalRules = append(finalRules, map[string]any{
					"action":     "block",
					"ip":         []string{"0.0.0.0/0", "::/0"},
					"blockDelay": "0",
				})
				force := "ForceIPv4"
				if strings.Contains(u.EgressIP, ":") {
					force = "ForceIPv6"
				}
				// Dedicated direct freedom outbound (no dialerProxy) so Xray enforces
				// finalRules strictly before dialing authorized downstream landings.
				outbounds = append(outbounds, map[string]any{
					"tag":         relayTag,
					"protocol":    "freedom",
					"sendThrough": u.EgressIP,
					"settings": map[string]any{
						"targetStrategy": force,
						"finalRules":     finalRules,
					},
				})
				rules = append(rules, map[string]any{
					"type":        "field",
					"inboundTag":  []string{tag},
					"user":        []string{u.Email},
					"source":      []string{sourceCIDR},
					"network":     "tcp",
					"outboundTag": relayTag,
				})
				rules = append(rules, map[string]any{
					"type":        "field",
					"inboundTag":  []string{tag},
					"user":        []string{u.Email},
					"outboundTag": "deny",
				})
			}
		}
	}
	return inbounds, outbounds, rules
}

func cloneEIHListeners(in []EIHListener) []EIHListener {
	if in == nil {
		return nil
	}
	out := slices.Clone(in)
	for i := range out {
		out[i].Users = slices.Clone(out[i].Users)
		for j := range out[i].Users {
			out[i].Users[j].RelayTargets = slices.Clone(out[i].Users[j].RelayTargets)
		}
	}
	return out
}
