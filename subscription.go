package glivela

import (
	"encoding/base64"
	"errors"
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

// subscriptionItem describes an actual output entry without its credential.
type subscriptionItem struct {
	Name     string       `json:"name"`
	Protocol ProtocolKind `json:"protocol"`
}

type resolvedSubscriptionEntry struct {
	subscriptionItem
	link   string
	routed bool
}

// resolveSubscription is the only final inventory path for both encodings and
// administrator previews through the rendered output.
func resolveSubscription(entries []NativeEntry, accountID string, mode PublishingMode, routes []PublishedRoute) ([]resolvedSubscriptionEntry, error) {
	native, err := nativeSubscriptionLines(entries, accountID)
	if err != nil {
		return nil, err
	}
	output, err := composeLinks(native, accountID, mode, routes, false)
	if err != nil {
		return nil, err
	}
	result := make([]resolvedSubscriptionEntry, 0, len(entries)+len(routes))
	names := map[string]bool{"DIRECT": true, "REJECT": true, "节点选择": true}
	if strings.TrimSpace(string(output)) == "" {
		return result, nil
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		protocol := VLESSReality
		if !strings.HasPrefix(line, "vless://") {
			protocol = Hysteria2
		}
		parsed, err := parseProtocolLink(line, protocol)
		if err != nil || names[parsed.Fragment] {
			return nil, errors.New("glivela: ambiguous subscription output")
		}
		names[parsed.Fragment] = true
		routed := slices.ContainsFunc(routes, func(item PublishedRoute) bool {
			return item.Grant.Publishable() && sameProtocolLinkIdentity(line, item.RouteLink, protocol)
		})
		result = append(result, resolvedSubscriptionEntry{subscriptionItem: subscriptionItem{Name: parsed.Fragment, Protocol: protocol}, link: line, routed: routed})
	}
	return result, nil
}

func RenderLinks(entries []NativeEntry, accountID string, mode PublishingMode, routes []PublishedRoute, encoded bool) ([]byte, error) {
	resolved, err := resolveSubscription(entries, accountID, mode, routes)
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, len(resolved))
	for _, entry := range resolved {
		lines = append(lines, entry.link)
	}
	result := []byte(strings.Join(lines, "\n") + "\n")
	if encoded {
		result = []byte(base64.StdEncoding.EncodeToString(result))
	}
	return result, nil
}

func RenderMihomo(entries []NativeEntry, accountID string, mode PublishingMode, routes []PublishedRoute) ([]byte, error) {
	resolved, err := resolveSubscription(entries, accountID, mode, routes)
	if err != nil {
		return nil, err
	}
	proxies := make([]any, 0, len(resolved))
	names := make([]any, 0, len(resolved)+1)
	for _, entry := range resolved {
		proxy, name, err := mihomoProxy(NativeEntry{Protocol: entry.Protocol, Link: entry.link})
		if err != nil {
			return nil, err
		}
		if entry.routed {
			proxy["udp"] = false
		}
		proxies = append(proxies, proxy)
		names = append(names, name)
	}
	names = append(names, "DIRECT")
	output, err := yaml.Marshal(map[string]any{
		"proxies":      proxies,
		"proxy-groups": []any{map[string]any{"name": "节点选择", "type": "select", "proxies": names}},
		"rules":        []any{"MATCH,节点选择"},
	})
	if err != nil {
		return nil, errors.New("glivela: cannot encode Mihomo subscription")
	}
	return output, nil
}

func nativeSubscriptionLines(entries []NativeEntry, accountID string) ([]byte, error) {
	if !ValidIdentifier(accountID) || len(entries) == 0 || len(entries) > 1024 {
		return nil, errors.New("glivela: invalid native subscription inventory")
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
			return nil, errors.New("glivela: invalid native subscription credential")
		}
		link, err := parseProtocolLink(strings.TrimSpace(entry.Link), entry.Protocol)
		if err != nil {
			return nil, errors.New("glivela: native subscription identity changed")
		}
		port, portErr := strconv.Atoi(link.Port())
		expectedIdentity := credential.Identity
		if entry.Protocol == Hysteria2 {
			expectedIdentity = entry.Material.HysteriaIdentity
		}
		if portErr != nil || port < 1 || port > 65535 || totalBytes > maxSubscriptionBytes || protocolLinkIdentity(link, entry.Protocol) != expectedIdentity || strings.TrimSpace(link.Fragment) == "" || len([]rune(link.Fragment)) > MaxDisplayNameLength || link.Query().Get("sni") == "" || entry.Protocol == VLESSReality && link.Query().Get("pbk") == "" {
			return nil, errors.New("glivela: native subscription identity changed")
		}
		name := compactSubscriptionName(strings.TrimSpace(link.Fragment))
		routeKey := string(entry.Protocol) + "\x00" + link.Host + "\x00" + link.Query().Get("sni") + "\x00" + link.Query().Get("pbk") + "\x00" + link.Query().Get("sid")
		if seenNames[name] || seenRoutes[routeKey] {
			return nil, errors.New("glivela: ambiguous native subscription inventory")
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
		return nil, "", errors.New("glivela: invalid subscription port")
	}
	query := link.Query()
	name := compactSubscriptionName(strings.TrimSpace(link.Fragment))
	if name == "" {
		return nil, "", errors.New("glivela: subscription name is required")
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
		return nil, errors.New("glivela: invalid subscription input")
	}
	plain := native
	if encoded {
		var err error
		plain, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(native)))
		if err != nil {
			return nil, errors.New("glivela: invalid native subscription")
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
			return nil, errors.New("glivela: route does not belong to this subscription")
		}
		baseKey := string(VLESSReality) + "\x00" + base.User.Username()
		if !identities[baseKey] || !slices.ContainsFunc(lines, func(line string) bool {
			return sameProtocolLinkIdentity(strings.TrimSpace(line), item.BaseLink, VLESSReality)
		}) {
			return nil, errors.New("glivela: route does not belong to this subscription")
		}
		routed, err := parseVLESSLink(item.RouteLink)
		if err != nil || !sameProtocolTransport(routed, base, VLESSReality) || routed.User.Username() == base.User.Username() || identities[string(VLESSReality)+"\x00"+routed.User.Username()] {
			return nil, errors.New("glivela: invalid routed credential")
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

func validatePublishedRouteScope(item PublishedRoute, accountID string) error {
	if item.EgressNameSuffix != "" && (!validDisplayName(item.EgressNameSuffix) || strings.ContainsAny(item.EgressNameSuffix, "|｜")) {
		return errors.New("glivela: invalid landing name suffix")
	}
	if item.Grant.Validate() != nil || item.Grant.AccountID != accountID || item.Protocol != VLESSReality || !ValidIdentity(item.BaseProtocolIdentity) || !ValidIdentity(item.RouteProtocolIdentity) || !validDisplayName(item.EntryName) || item.EgressRegionPrefix != "" && (!validDisplayName(item.EgressRegionPrefix) || strings.ContainsAny(item.EgressRegionPrefix, "|｜")) {
		return errors.New("glivela: published route scope does not match")
	}
	return nil
}

func validatePublishedRouteLinks(item PublishedRoute) error {
	base, err := parseVLESSLink(item.BaseLink)
	if err != nil || protocolLinkIdentity(base, VLESSReality) != item.BaseProtocolIdentity {
		return errors.New("glivela: native credential changed")
	}
	routed, err := parseVLESSLink(item.RouteLink)
	if err != nil || protocolLinkIdentity(routed, VLESSReality) != item.RouteProtocolIdentity {
		return errors.New("glivela: routed credential changed")
	}
	if item.BaseProtocolIdentity != item.Grant.Base.Identity || item.RouteProtocolIdentity != item.Grant.Route.Identity {
		return errors.New("glivela: VLESS route credential changed")
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
