package glivela

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed subscription_profiles/aethersailor-full.json
var aethersailorFull []byte

type subscriptionProfileGroup struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Members   []string `json:"members"`
	Pattern   string   `json:"pattern"`
	Other     bool     `json:"other"`
	URL       string   `json:"url"`
	Interval  int      `json:"interval"`
	Tolerance int      `json:"tolerance"`
}

// RenderAethersailorProfile wraps the already-authorized Mihomo inventory.
// It never edits proxy transport settings, credentials, ordering or helpers.
func RenderAethersailorProfile(body []byte, items []SubscriptionItem) ([]byte, error) {
	if len(items) == 0 {
		return nil, errors.New("subscription profile: no selectable nodes")
	}
	var template struct {
		Groups    []subscriptionProfileGroup `json:"groups"`
		Rules     [][]string                 `json:"rules"`
		Providers map[string]any             `json:"providers"`
	}
	if err := json.Unmarshal(aethersailorFull, &template); err != nil {
		return nil, err
	}
	var original struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(body, &original); err != nil {
		return nil, err
	}
	occupied := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, proxy := range original.Proxies {
		name, ok := proxy["name"].(string)
		if !ok || name == "" || occupied[name] {
			return nil, errors.New("subscription profile: invalid proxy name")
		}
		occupied[name] = true
	}
	matched := map[string][]string{}
	categorized := map[string]bool{}
	for _, group := range template.Groups {
		if group.Pattern == "" {
			continue
		}
		pattern, err := regexp.Compile(group.Pattern)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if !occupied[item.Name] {
				return nil, errors.New("subscription profile: missing selectable proxy")
			}
			if pattern.MatchString(item.Name) {
				matched[group.Name] = append(matched[group.Name], item.Name)
				if group.Pattern != "(?i).*" {
					categorized[item.Name] = true
				}
			}
		}
	}
	for _, group := range template.Groups {
		if group.Other {
			for _, item := range items {
				if !categorized[item.Name] {
					matched[group.Name] = append(matched[group.Name], item.Name)
				}
			}
		}
	}
	// Reserve all surviving group names before resolving forward references.
	names := map[string]string{"DIRECT": "DIRECT", "REJECT": "REJECT"}
	for _, group := range template.Groups {
		if group.Type == "url-test" && len(matched[group.Name]) == 0 {
			continue
		}
		name := group.Name
		for suffix := 2; occupied[name]; suffix++ {
			name = fmt.Sprintf("%s · %d", group.Name, suffix)
		}
		occupied[name] = true
		names[group.Name] = name
	}
	groups := []map[string]any{}
	for _, group := range template.Groups {
		name, ok := names[group.Name]
		if !ok {
			continue
		}
		members := []string{}
		for _, reference := range group.Members {
			if resolved, exists := names[reference]; exists {
				members = append(members, resolved)
			}
		}
		members = append(members, matched[group.Name]...)
		if len(members) == 0 {
			return nil, errors.New("subscription profile: empty group")
		}
		value := map[string]any{"name": name, "type": group.Type, "proxies": members}
		if group.Type == "url-test" {
			value["url"], value["interval"], value["tolerance"] = group.URL, group.Interval, group.Tolerance
			value["lazy"] = true
		}
		groups = append(groups, value)
	}
	rules := make([]string, 0, len(template.Rules))
	for _, rule := range template.Rules {
		target := 2
		if len(rule) == 2 && rule[0] == "MATCH" {
			target = 1
		}
		if len(rule) <= target || names[rule[target]] == "" {
			return nil, errors.New("subscription profile: invalid rule target")
		}
		rule[target] = names[rule[target]]
		rules = append(rules, strings.Join(rule, ","))
	}
	output, err := yaml.Marshal(map[string]any{"proxies": original.Proxies, "proxy-groups": groups, "rules": rules, "rule-providers": template.Providers})
	if err != nil {
		return nil, err
	}
	header := "# Aethersailor Full, adapted by Glivela; CC BY-SA 4.0.\n# https://github.com/Aethersailor/Custom_OpenClash_Rules/tree/882e404049f0cfce5d2438efb8943527f9284caf\n# https://creativecommons.org/licenses/by-sa/4.0/\n# No DNS or local network settings included.\n"
	if len(output)+len(header) > maxSubscriptionBytes {
		return nil, errors.New("subscription profile: output too large")
	}
	return append([]byte(header), output...), nil
}
