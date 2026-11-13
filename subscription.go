package glivela

import (
	"cmp"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxSubscriptionBytes = 4 << 20

type PublishedRoute struct {
	Name                   string       `json:"name,omitempty"`
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

// SubscriptionItem identifies an actual selectable output without its credential.
type SubscriptionItem struct {
	ID       string       `json:"id"`
	Kind     string       `json:"kind"`
	Name     string       `json:"name"`
	Protocol ProtocolKind `json:"protocol"`
}

type resolvedSubscriptionEntry struct {
	SubscriptionItem
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
		item := SubscriptionItem{Name: parsed.Fragment, Protocol: protocol, Kind: "native"}
		for _, entry := range entries {
			if entry.Protocol == protocol && sameProtocolLinkIdentity(line, entry.Link, protocol) {
				item.ID = "native/" + string(protocol) + "/" + entry.Material.Credential.ID
				break
			}
		}
		for _, route := range routes {
			if route.Grant.Publishable() && sameProtocolLinkIdentity(line, route.RouteLink, protocol) {
				item.ID, item.Kind = "route/"+route.Grant.ID, "route"
				break
			}
		}
		if item.ID == "" {
			return nil, errors.New("glivela: subscription item has no owned identity")
		}
		result = append(result, resolvedSubscriptionEntry{SubscriptionItem: item, link: line, routed: item.Kind == "route"})
	}
	return result, nil
}

func RenderLinks(entries []NativeEntry, accountID string, mode PublishingMode, routes []PublishedRoute, order []string, encoded bool) ([]byte, error) {
	resolved, err := resolveSubscription(entries, accountID, mode, routes)
	if err != nil {
		return nil, err
	}
	ranks := subscriptionRanks(order, resolved)
	slices.SortStableFunc(resolved, func(a, b resolvedSubscriptionEntry) int {
		return cmp.Compare(ranks.position(a.ID), ranks.position(b.ID))
	})
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

type PublishedClientChain struct {
	Chain              ClientChain
	Base               NativeEntry
	Server             string
	EgressRegionPrefix string
	EgressNameSuffix   string
}

func RenderMihomo(entries []NativeEntry, accountID string, mode PublishingMode, routes []PublishedRoute, order []string, chains ...PublishedClientChain) ([]byte, []SubscriptionItem, error) {
	var resolved []resolvedSubscriptionEntry
	var err error
	if len(entries) != 0 || len(chains) == 0 {
		resolved, err = resolveSubscription(entries, accountID, mode, routes)
	}
	if err != nil {
		return nil, nil, err
	}
	type proxyEntry struct {
		SubscriptionItem
		value   map[string]any
		helpers []string
	}
	values := make([]proxyEntry, 0, len(resolved)+len(chains))
	helperValues := map[string]map[string]any{}
	names := make([]any, 0, len(resolved)+1)
	for _, entry := range resolved {
		proxy, name, err := mihomoProxy(NativeEntry{Protocol: entry.Protocol, Link: entry.link})
		if err != nil {
			return nil, nil, err
		}
		if entry.routed {
			proxy["udp"] = false
		}
		values = append(values, proxyEntry{SubscriptionItem: entry.SubscriptionItem, value: proxy})
		names = append(names, name)
	}
	used := map[string]bool{"DIRECT": true, "REJECT": true, "节点选择": true}
	for _, name := range names {
		used[name.(string)] = true
	}
	chains = slices.Clone(chains)
	slices.SortFunc(chains, func(a, b PublishedClientChain) int { return strings.Compare(a.Chain.ID, b.Chain.ID) })
	helpers := map[string]string{}
	for _, published := range chains {
		c := published.Chain
		validServer := (c.Transport == "" || c.Transport == IPv4ClientSS2022) && PublicTransportIPv4(published.Server) || c.Transport == "ipv6-ss2022" && published.Server == c.ServerIPv6 && PublicTransportIPv6(published.Server)
		if c.PrivateLink != nil {
			validServer = published.Server == c.PrivateLink.Address && c.PrivateLink.Validate() == nil
		}
		if c.Validate() != nil || (published.EgressRegionPrefix != "" && !validDisplayName(published.EgressRegionPrefix)) || (published.EgressNameSuffix != "" && (!validDisplayName(published.EgressNameSuffix) || strings.ContainsAny(published.EgressNameSuffix, "|｜"))) || !c.Enabled || c.AccountID != accountID || !validServer || published.Base.Protocol != VLESSReality || published.Base.Material.Credential.EntryID != c.EntryID {
			return nil, nil, errors.New("glivela: invalid published client chain")
		}
		if _, err := nativeSubscriptionLines([]NativeEntry{published.Base}, accountID); err != nil {
			return nil, nil, err
		}
		base, entryName, err := mihomoProxy(published.Base)
		if err != nil {
			return nil, nil, err
		}
		nameText := routeName(PublishedRoute{EntryName: entryName, EgressRegionPrefix: published.EgressRegionPrefix, EgressNameSuffix: published.EgressNameSuffix}) + "·链"
		if c.Transport == "ipv6-ss2022" {
			// New IPv6 chains use the operator's name so different landings are
			// distinguishable; retain established names for existing chains.
			nameText = c.Name
		}
		name := uniqueSubscriptionName(nameText, used)
		helper := helpers[published.Base.Material.Credential.ID]
		if helper == "" {
			if _, entry, ok := strings.Cut(entryName, "｜"); ok {
				entryName = entry
			}
			helper = uniqueSubscriptionName("入口｜"+compactEntryName(entryName), used)
			helpers[published.Base.Material.Credential.ID] = helper
			base["name"], base["udp"] = helper, false
			helperValues[helper] = base
		}
		cipher := "aes-256-gcm"
		if c.Transport == IPv4ClientSS2022 {
			cipher = IPv4ClientSS2022Method
		}
		if c.Transport == "ipv6-ss2022" || c.Shared {
			cipher = SS2022Method
		}
		dependencies := []string{helper}
		if c.Relay != nil {
			relayName := uniqueSubscriptionName("中转｜"+c.Name, used)
			relayServer, relayCipher := c.Relay.ServerIPv6, SS2022Method
			if c.Relay.Transport == IPv4RelaySS2022 {
				relayServer, relayCipher = c.Relay.ServerIPv4, IPv4ClientSS2022Method
			}
			helperValues[relayName] = map[string]any{"name": relayName, "type": "ss", "server": relayServer, "port": c.Relay.Port, "cipher": relayCipher, "password": c.Relay.Key, "udp": false, "dialer-proxy": helper}
			dependencies = append(dependencies, relayName)
			helper = relayName
		}
		values = append(values, proxyEntry{SubscriptionItem: SubscriptionItem{ID: "chain/" + c.ID, Name: name, Kind: "chain", Protocol: ProtocolKind("shadowsocks")}, helpers: dependencies, value: map[string]any{"name": name, "type": "ss", "server": published.Server, "port": c.Port, "cipher": cipher, "password": c.Key, "udp": false, "dialer-proxy": helper}})
	}
	ranks := subscriptionRanks(order, resolved)
	slices.SortStableFunc(values, func(a, b proxyEntry) int { return cmp.Compare(ranks.position(a.ID), ranks.position(b.ID)) })
	proxies := make([]any, 0, len(values)+len(helperValues))
	items := make([]SubscriptionItem, 0, len(values))
	names = make([]any, 0, len(values)+1)
	addedHelpers := map[string]bool{}
	for _, entry := range values {
		for _, helper := range entry.helpers {
			if !addedHelpers[helper] {
				proxies = append(proxies, helperValues[helper])
				addedHelpers[helper] = true
			}
		}
		proxies = append(proxies, entry.value)
		names = append(names, entry.Name)
		items = append(items, entry.SubscriptionItem)
	}
	names = append(names, "DIRECT")
	output, err := yaml.Marshal(map[string]any{
		"proxies":      proxies,
		"proxy-groups": []any{map[string]any{"name": "节点选择", "type": "select", "proxies": names}},
		"rules":        []any{"MATCH,节点选择"},
	})
	if err != nil {
		return nil, nil, errors.New("glivela: cannot encode Mihomo subscription")
	}
	return output, items, nil
}

// Keep existing route names unchanged; only colliding additions receive a
// readable number. Internal credential and chain IDs never enter display names.
func uniqueSubscriptionName(name string, used map[string]bool) string {
	candidate := name
	for number := 2; used[candidate]; number++ {
		candidate = name + "·" + strconv.Itoa(number)
	}
	used[candidate] = true
	return candidate
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
	realityOptions := map[string]any{
		"public-key": query.Get("pbk"), "short-id": query.Get("sid"),
		"support-x25519mlkem768": true,
	}
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
	if item.Name != "" && (item.Grant.ClientChainID == "" || !validDisplayName(item.Name)) {
		return errors.New("glivela: invalid server chain name")
	}
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

// compactEntryName preserves the operator-provided label without vendor aliases.
func compactEntryName(name string) string {
	return strings.TrimSpace(name)
}

func compactSubscriptionName(name string) string {
	prefix, entry, ok := strings.Cut(name, "｜")
	if !ok {
		return compactEntryName(name)
	}
	return prefix + "｜" + compactEntryName(entry)
}

func routeName(item PublishedRoute) string {
	if item.Name != "" {
		return item.Name
	}
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
