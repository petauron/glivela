package glivela

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed subscription_profiles/shadowrocket-custom-rules.json
var shadowrocketCustomRules []byte

// RenderShadowrocketProfile renders native policy configuration for the same
// node subscription. Shadowrocket keeps subscribed nodes separate from .conf
// files: exact names bind these groups to the unchanged native node inventory.
// No General, Host, DNS, scripts, rewrites or local override sections are emitted.
func RenderShadowrocketProfile(body []byte) ([]byte, error) {
	var profile struct {
		Groups []struct {
			Name     string   `yaml:"name"`
			Type     string   `yaml:"type"`
			Proxies  []string `yaml:"proxies"`
			URL      string   `yaml:"url"`
			Interval int      `yaml:"interval"`
		} `yaml:"proxy-groups"`
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(body, &profile); err != nil {
		return nil, err
	}
	var custom map[string][]string
	if err := json.Unmarshal(shadowrocketCustomRules, &custom); err != nil {
		return nil, err
	}
	var out strings.Builder
	out.WriteString("# Glivela: Aethersailor Full for Shadowrocket; CC BY-SA 4.0.\n# Import the matching Shadowrocket native node subscription first; preserve its names/order.\n# Keep local DNS and company/private overrides in your local configuration.\n# Compatibility: DOMAIN-REGEX in upstream rule sets and SRC-PORT are unsupported.\n# Unmatched traffic follows later rules or FINAL; this is not an exact Mihomo equivalent.\n# https://github.com/Aethersailor/Custom_OpenClash_Rules/tree/882e404049f0cfce5d2438efb8943527f9284caf\n# https://creativecommons.org/licenses/by-sa/4.0/\n\n[Proxy Group]\n")
	for _, g := range profile.Groups {
		if !shadowrocketPolicyName(g.Name) || len(g.Proxies) == 0 || (g.Type != "select" && g.Type != "url-test") {
			return nil, errors.New("subscription profile: unsupported Shadowrocket group")
		}
		for _, name := range g.Proxies {
			if !shadowrocketPolicyName(name) {
				return nil, errors.New("subscription profile: unsupported Shadowrocket policy name")
			}
		}
		fmt.Fprintf(&out, "%s = %s, %s", g.Name, g.Type, strings.Join(g.Proxies, ", "))
		if g.Type == "url-test" {
			fmt.Fprintf(&out, ", url=%s, interval=%d", g.URL, g.Interval)
		}
		out.WriteByte('\n')
	}
	out.WriteString("\n[Rule]\n")
	const geo = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/2963a49408bbc37f2c2ffa6e8329fe11076a816b/geo/"
	for _, raw := range profile.Rules {
		r := strings.Split(raw, ",")
		if len(r) == 2 && r[0] == "MATCH" {
			fmt.Fprintf(&out, "FINAL,%s\n", r[1])
			continue
		}
		if len(r) < 3 {
			return nil, errors.New("subscription profile: invalid Shadowrocket rule")
		}
		switch r[0] {
		case "GEOSITE":
			fmt.Fprintf(&out, "RULE-SET,%sgeosite/classical/%s.list,%s\n", geo, r[1], r[2])
		case "GEOIP":
			// Non-country GeoIP categories use the same upstream data as explicit
			// classical CIDRs; Shadowrocket's GEOIP keyword only takes countries.
			fmt.Fprintf(&out, "RULE-SET,%sgeoip/classical/%s.list,%s,no-resolve\n", geo, r[1], r[2])
		case "RULE-SET":
			entries, ok := custom[r[1]]
			if !ok {
				return nil, errors.New("subscription profile: unknown Shadowrocket rule set")
			}
			for _, entry := range entries {
				v := strings.Split(entry, ",")
				if len(v) < 2 {
					return nil, errors.New("subscription profile: invalid custom rule")
				}
				if v[0] == "SRC-PORT" {
					out.WriteString("# SRC-PORT bypass omitted: unavailable in Shadowrocket native rules.\n")
					continue
				}
				if v[0] == "IP-CIDR6" {
					v[0] = "IP-CIDR"
				}
				line := []string{v[0], v[1], r[2]}
				line = append(line, v[2:]...)
				out.WriteString(strings.Join(line, ","))
				out.WriteByte('\n')
			}
		default:
			return nil, errors.New("subscription profile: unsupported Shadowrocket rule")
		}
	}
	if out.Len() > maxSubscriptionBytes {
		return nil, errors.New("subscription profile: output too large")
	}
	return []byte(out.String()), nil
}

func shadowrocketPolicyName(name string) bool {
	return name != "" && strings.TrimSpace(name) == name && !strings.ContainsAny(name, ",=\r\n\x00\"\\[]")
}
