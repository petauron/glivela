package meridian

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxSubscriptionBytes = 4 << 20

type PublishedRoute struct {
	Grant                  RouteGrant   `json:"grant"`
	Protocol               ProtocolKind `json:"protocol"`
	EntryName              string       `json:"entryName"`
	EgressNameSuffix       string       `json:"egressNameSuffix,omitempty"`
	EgressRegionPrefix     string       `json:"egressRegionPrefix,omitempty"`
	IPv4EgressRegionPrefix string       `json:"ipv4EgressRegionPrefix,omitempty"`
	BaseLink               string       `json:"baseLink"`
	RouteLink              string       `json:"routeLink"`
	BaseProtocolIdentity   string       `json:"baseProtocolIdentity"`
	RouteProtocolIdentity  string       `json:"routeProtocolIdentity"`
}

type NativeEntry struct {
	Material CredentialMaterial `json:"material"`
	Protocol ProtocolKind       `json:"protocol"`
	Link     string             `json:"link"`
}

func RenderLinks(entries []NativeEntry, accountID string, mode PublishingMode, routes []PublishedRoute, encoded bool) ([]byte, error) {
	plain, err := nativeSubscriptionLines(entries, accountID)
	if err != nil {
		return nil, err
	}
	if encoded {
		plain = []byte(base64.StdEncoding.EncodeToString(plain))
	}
	return composeLinks(plain, accountID, mode, routes, encoded)
}

func RenderMihomo(entries []NativeEntry, accountID string, mode PublishingMode, routes []PublishedRoute) ([]byte, error) {
	if _, err := nativeSubscriptionLines(entries, accountID); err != nil {
		return nil, err
	}
	proxies := make([]any, 0, len(entries))
	names := make([]any, 0, len(entries)+1)
	for _, entry := range entries {
		proxy, name, err := mihomoProxy(entry)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, proxy)
		names = append(names, name)
	}
	names = append(names, "DIRECT")
	config := map[string]any{
		"proxies":      proxies,
		"proxy-groups": []any{map[string]any{"name": "节点选择", "type": "select", "proxies": names}},
		"rules":        []any{"MATCH,节点选择"},
	}
	native, err := yaml.Marshal(config)
	if err != nil {
		return nil, errors.New("meridian: cannot encode Mihomo subscription")
	}
	return composeMihomo(native, accountID, mode, routes)
}

func nativeSubscriptionLines(entries []NativeEntry, accountID string) ([]byte, error) {
	if !ValidIdentifier(accountID) || len(entries) == 0 || len(entries) > 1024 {
		return nil, errors.New("meridian: invalid native subscription inventory")
	}
	seenNames, seenRoutes := map[string]bool{}, map[string]bool{}
	seenCredentials := map[string]bool{}
	lines := make([]string, 0, len(entries))
	totalBytes := 0
	for _, entry := range entries {
		totalBytes += len(entry.Link)
		credential := entry.Material.Credential
		credentialKey := credential.ID + "\x00" + string(entry.Protocol)
		if entry.Material.Validate() != nil || !entry.Protocol.Valid() || credential.Kind != NativeCredential || credential.AccountID != accountID || !credential.Enabled || seenCredentials[credentialKey] {
			return nil, errors.New("meridian: invalid native subscription credential")
		}
		link, err := parseProtocolLink(strings.TrimSpace(entry.Link), entry.Protocol)
		if err != nil {
			return nil, errors.New("meridian: native subscription identity changed")
		}
		port, portErr := strconv.Atoi(link.Port())
		expectedIdentity := credential.Identity
		if entry.Protocol == Hysteria2 {
			expectedIdentity = entry.Material.HysteriaIdentity
		}
		if portErr != nil || port < 1 || port > 65535 || totalBytes > maxSubscriptionBytes || protocolLinkIdentity(link, entry.Protocol) != expectedIdentity || strings.TrimSpace(link.Fragment) == "" || len([]rune(link.Fragment)) > MaxDisplayNameLength || link.Query().Get("sni") == "" || entry.Protocol == VLESSReality && link.Query().Get("pbk") == "" {
			return nil, errors.New("meridian: native subscription identity changed")
		}
		name := compactSubscriptionName(strings.TrimSpace(link.Fragment))
		routeKey := string(entry.Protocol) + "\x00" + link.Host + "\x00" + link.Query().Get("sni") + "\x00" + link.Query().Get("pbk") + "\x00" + link.Query().Get("sid")
		if seenNames[name] || seenRoutes[routeKey] {
			return nil, errors.New("meridian: ambiguous native subscription inventory")
		}
		seenNames[name], seenRoutes[routeKey], seenCredentials[credentialKey] = true, true, true
		line := strings.TrimSpace(entry.Link)
		if name != strings.TrimSpace(link.Fragment) {
			raw, _, _ := strings.Cut(line, "#")
			line = raw + "#" + escapeLinkFragment(name)
		}
		lines = append(lines, line)
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func mihomoProxy(entry NativeEntry) (map[string]any, string, error) {
	link, err := parseProtocolLink(strings.TrimSpace(entry.Link), entry.Protocol)
	if err != nil {
		return nil, "", err
	}
	port, err := strconv.Atoi(link.Port())
	if err != nil || !validPort(port) {
		return nil, "", errors.New("meridian: invalid subscription port")
	}
	query := link.Query()
	name := compactSubscriptionName(strings.TrimSpace(link.Fragment))
	if name == "" {
		return nil, "", errors.New("meridian: subscription name is required")
	}
	if entry.Protocol == Hysteria2 {
		return map[string]any{
			"name": name, "type": "hysteria2", "server": link.Hostname(), "port": port,
			"password": link.User.Username(), "sni": query.Get("sni"), "alpn": []string{"h3"},
			"skip-cert-verify": false, "udp": true,
		}, name, nil
	}
	realityOptions := map[string]any{"public-key": query.Get("pbk"), "short-id": query.Get("sid")}
	if spiderX := query.Get("spx"); spiderX != "" {
		realityOptions["spider-x"] = spiderX
	}
	proxy := map[string]any{
		"name": name, "type": "vless", "server": link.Hostname(), "port": port,
		"uuid": link.User.Username(), "network": query.Get("type"), "tls": true,
		"servername": query.Get("sni"), "flow": query.Get("flow"), "udp": true,
		"reality-opts": realityOptions,
	}
	if fingerprint := query.Get("fp"); fingerprint != "" {
		proxy["client-fingerprint"] = fingerprint
	}
	return proxy, name, nil
}

func composeLinks(native []byte, accountID string, mode PublishingMode, routes []PublishedRoute, encoded bool) ([]byte, error) {
	if len(native) > maxSubscriptionBytes || !ValidIdentifier(accountID) || !mode.Valid() {
		return nil, errors.New("meridian: invalid subscription input")
	}
	plain := native
	if encoded {
		var err error
		plain, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(native)))
		if err != nil {
			return nil, errors.New("meridian: invalid native subscription")
		}
	}
	lines := strings.Split(strings.TrimRight(string(plain), "\r\n"), "\n")
	identities := map[string]bool{}
	routeLabels := compositeRouteLabels(routes)
	for _, line := range lines {
		if link, err := parseVLESSLink(strings.TrimSpace(line)); err == nil {
			identities[string(VLESSReality)+"\x00"+link.User.Username()] = true
			continue
		}
		if link, err := parseHysteria2Link(strings.TrimSpace(line)); err == nil {
			identities[string(Hysteria2)+"\x00"+link.User.Username()] = true
		}
	}
	for _, item := range routes {
		if err := validatePublishedRouteScope(item, accountID); err != nil {
			return nil, err
		}
		if !item.Grant.Publishable() || !mode.Valid() || !item.Grant.Mode.Valid() {
			continue
		}
		if err := validatePublishedRouteLinks(item); err != nil {
			return nil, err
		}
		base, err := parseVLESSLink(item.BaseLink)
		if err != nil {
			return nil, errors.New("meridian: route does not belong to this subscription")
		}
		baseKey := string(VLESSReality) + "\x00" + base.User.Username()
		if !identities[baseKey] || !slices.ContainsFunc(lines, func(line string) bool {
			return sameProtocolLinkIdentity(strings.TrimSpace(line), item.BaseLink, VLESSReality)
		}) {
			return nil, errors.New("meridian: route does not belong to this subscription")
		}
		routed, err := parseVLESSLink(item.RouteLink)
		if err != nil || !sameProtocolTransport(routed, base, VLESSReality) || routed.User.Username() == base.User.Username() || identities[string(VLESSReality)+"\x00"+routed.User.Username()] {
			return nil, errors.New("meridian: invalid routed credential")
		}
		routeLink, _, _ := strings.Cut(strings.TrimSpace(item.RouteLink), "#")
		name := routeName(item)
		if label := routeLabels[item.Grant.ID]; label != "" {
			name = label
		}
		lines = append(lines, routeLink+"#"+escapeLinkFragment(name))
		identities[string(VLESSReality)+"\x00"+routed.User.Username()] = true
	}
	lines = slices.DeleteFunc(lines, func(line string) bool {
		return slices.ContainsFunc(routes, func(item PublishedRoute) bool {
			return item.Grant.Publishable() && item.Grant.HideNative && sameProtocolLinkIdentity(strings.TrimSpace(line), item.BaseLink, VLESSReality)
		})
	})
	result := []byte(strings.Join(lines, "\n") + "\n")
	if encoded {
		result = []byte(base64.StdEncoding.EncodeToString(result))
	}
	return result, nil
}

func composeMihomo(native []byte, accountID string, mode PublishingMode, routes []PublishedRoute) ([]byte, error) {
	if len(native) > maxSubscriptionBytes || !ValidIdentifier(accountID) || !mode.Valid() {
		return nil, errors.New("meridian: invalid subscription input")
	}
	var config map[string]any
	if yaml.Unmarshal(native, &config) != nil || config == nil {
		return nil, errors.New("meridian: invalid native Mihomo configuration")
	}
	proxies, ok := config["proxies"].([]any)
	if !ok {
		return nil, errors.New("meridian: native subscription has no proxy inventory")
	}
	groups, ok := config["proxy-groups"].([]any)
	if !ok && config["proxy-groups"] != nil {
		return nil, errors.New("meridian: invalid native proxy groups")
	}
	names := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, values := range [][]any{proxies, groups} {
		for _, value := range values {
			entry, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("meridian: invalid native subscription entry")
			}
			name, _ := entry["name"].(string)
			if name == "" || names[name] {
				return nil, errors.New("meridian: ambiguous native subscription names")
			}
			names[name] = true
		}
	}
	reserve := func(name string) error {
		if names[name] {
			return errors.New("meridian: managed subscription name conflicts with native configuration")
		}
		names[name] = true
		return nil
	}
	baseProxies := slices.Clone(proxies)
	routeLabels := compositeRouteLabels(routes)
	routeNames := []any{}
	replacements := map[string][]any{}
	for _, item := range routes {
		if err := validatePublishedRouteScope(item, accountID); err != nil {
			return nil, err
		}
		if !item.Grant.Publishable() {
			continue
		}
		if err := validatePublishedRouteLinks(item); err != nil {
			return nil, err
		}
		base, err := parseVLESSLink(item.BaseLink)
		if err != nil {
			return nil, err
		}
		proxyType, credentialField := "vless", "uuid"
		var proxy map[string]any
		for _, value := range baseProxies {
			candidate := value.(map[string]any)
			if candidate["type"] == proxyType && candidate[credentialField] == base.User.Username() && candidate["server"] == base.Hostname() && fmt.Sprint(candidate["port"]) == base.Port() {
				if proxy != nil {
					return nil, errors.New("meridian: ambiguous native entry identity")
				}
				proxy = candidate
			}
		}
		if proxy == nil || proxy["dialer-proxy"] != nil || !sameMihomoRealityTransport(proxy, base) {
			return nil, errors.New("meridian: native entry does not match this account")
		}
		routed, err := parseVLESSLink(item.RouteLink)
		if err != nil || !sameProtocolTransport(routed, base, VLESSReality) || routed.User.Username() == base.User.Username() {
			return nil, errors.New("meridian: invalid routed subscription identity")
		}
		for _, value := range proxies {
			candidate := value.(map[string]any)
			if candidate["type"] == proxyType && candidate[credentialField] == routed.User.Username() {
				return nil, errors.New("meridian: duplicated routed subscription identity")
			}
		}
		name := routeName(item)
		if label := routeLabels[item.Grant.ID]; label != "" {
			name = label
		}
		if err := reserve(name); err != nil {
			return nil, err
		}
		clone := make(map[string]any, len(proxy))
		for key, value := range proxy {
			clone[key] = value
		}
		clone["name"], clone[credentialField], clone["udp"] = name, routed.User.Username(), false
		proxies = append(proxies, clone)
		routeNames = append(routeNames, name)
		if item.Grant.HideNative {
			original := proxy["name"].(string)
			replacements[original] = append(replacements[original], name)
		}
	}
	for _, value := range groups {
		group := value.(map[string]any)
		if members, ok := group["proxies"].([]any); ok {
			updated := make([]any, 0, len(members))
			for _, member := range members {
				name, ok := member.(string)
				if !ok {
					return nil, errors.New("meridian: invalid native group member")
				}
				if replacement := replacements[name]; len(replacement) > 0 {
					updated = append(updated, replacement...)
				} else {
					updated = append(updated, member)
				}
			}
			group["proxies"] = updated
		}
		if group["type"] == "select" {
			if members, ok := group["proxies"].([]any); ok {
				for _, name := range routeNames {
					if !slices.Contains(members, name) {
						members = append(members, name)
					}
				}
				group["proxies"] = members
			}
		}
	}
	proxies = slices.DeleteFunc(proxies, func(value any) bool {
		name, _ := value.(map[string]any)["name"].(string)
		return len(replacements[name]) > 0
	})
	if rules, ok := config["rules"].([]any); ok {
		for index, value := range rules {
			if rule, ok := value.(string); ok {
				parts := strings.Split(rule, ",")
				target := len(parts) - 1
				if parts[target] == "no-resolve" && target > 0 {
					target--
				}
				if replacement := replacements[parts[target]]; len(replacement) > 0 {
					parts[target] = replacement[0].(string)
					rules[index] = strings.Join(parts, ",")
				}
			}
		}
	}
	config["proxies"], config["proxy-groups"] = proxies, groups
	output, err := yaml.Marshal(config)
	if err != nil {
		return nil, errors.New("meridian: cannot encode Mihomo subscription")
	}
	return output, nil
}

func validatePublishedRouteScope(item PublishedRoute, accountID string) error {
	if item.EgressNameSuffix != "" && (!validDisplayName(item.EgressNameSuffix) || strings.ContainsAny(item.EgressNameSuffix, "|｜")) {
		return errors.New("meridian: invalid landing name suffix")
	}
	if item.Grant.Validate() != nil || item.Grant.AccountID != accountID || item.Protocol != VLESSReality || !ValidIdentity(item.BaseProtocolIdentity) || !ValidIdentity(item.RouteProtocolIdentity) || !validDisplayName(item.EntryName) || item.EgressRegionPrefix != "" && (!validDisplayName(item.EgressRegionPrefix) || strings.ContainsAny(item.EgressRegionPrefix, "|｜")) {
		return errors.New("meridian: published route scope does not match")
	}
	return nil
}

func validatePublishedRouteLinks(item PublishedRoute) error {
	base, err := parseVLESSLink(item.BaseLink)
	if err != nil || protocolLinkIdentity(base, VLESSReality) != item.BaseProtocolIdentity {
		return errors.New("meridian: native credential changed")
	}
	routed, err := parseVLESSLink(item.RouteLink)
	if err != nil || protocolLinkIdentity(routed, VLESSReality) != item.RouteProtocolIdentity {
		return errors.New("meridian: routed credential changed")
	}
	if item.BaseProtocolIdentity != item.Grant.Base.Identity || item.RouteProtocolIdentity != item.Grant.Route.Identity {
		return errors.New("meridian: VLESS route credential changed")
	}
	return nil
}

// compactEntryName keeps distinct circuit types and instance numbers. Unknown
// names remain unchanged rather than losing user-provided identification.
func compactEntryName(name string) string {
	switch strings.TrimSpace(name) {
	case "AKKO-CN2":
		return "AKKO-CN2"
	case "VMISS-CN2":
		return "VMISS-CN2"
	case "DataWave-CN2":
		return "DW-CN2"
	case "ShanDun-CN2":
		return "SD-CN2"
	case "CN2 FXTRANSIT":
		return "FX-CN2"
	case "MatrixIDC CN2-1":
		return "MX-CN2①"
	case "MatrixIDC CN2-2":
		return "MX-CN2②"
	case "MatrixIDC 4837-1":
		return "MX-4837①"
	case "MatrixIDC 4837-2":
		return "MX-4837②"
	default:
		return strings.TrimSpace(name)
	}
}

func compactSubscriptionName(name string) string {
	prefix, entry, ok := strings.Cut(name, "｜")
	if !ok {
		return compactEntryName(name)
	}
	return prefix + "｜" + compactEntryName(entry)
}

func routeName(item PublishedRoute) string {
	entry := strings.TrimSpace(item.EntryName)
	if _, name, ok := strings.Cut(entry, "｜"); ok && strings.TrimSpace(name) != "" {
		entry = name
	}
	entry = compactEntryName(strings.TrimLeft(entry, "｜| "))
	label := item.EgressNameSuffix
	if item.Grant.IPv4EgressID != "" && label == "" {
		label = "IPv6优先+IPv4"
	}
	if label == "" {
		label = "双跳"
	}
	entry = label + "·" + entry
	prefix := item.EgressRegionPrefix
	if prefix == "" {
		prefix = "落地"
	}
	if item.Grant.IPv4EgressID != "" {
		four := item.IPv4EgressRegionPrefix
		if four == "" {
			four = "IPv4落地"
		}
		if four != prefix {
			prefix += " + " + four
		}
	}
	return prefix + "｜" + entry
}

// Only new combinations are disambiguated; existing single-exit names stay
// byte-for-byte unchanged. Never append credential IDs or opaque node hashes.
func compositeRouteLabels(routes []PublishedRoute) map[string]string {
	groups := map[string][]string{}
	singleNames := map[string]bool{}
	for _, route := range routes {
		if route.Grant.IPv4EgressID != "" {
			name := routeName(route)
			groups[name] = append(groups[name], route.Grant.ID)
		} else {
			singleNames[routeName(route)] = true
		}
	}
	labels := map[string]string{}
	for name, ids := range groups {
		slices.Sort(ids)
		for i, id := range ids {
			label := name
			if len(ids) > 1 || singleNames[name] {
				if i < 20 {
					label += string(rune('①') + rune(i))
				} else {
					label += "·" + strconv.Itoa(i+1)
				}
			}
			labels[id] = label
		}
	}
	return labels
}
