package glivela

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultRealityPort      = 443
	RealityBackendPort      = 10443
	DefaultLandingSOCKSPort = 1080
	XrayAPIListenPort       = 10085
	XrayMinimumClient       = "0.0.0"
)

type CredentialMaterial struct {
	Credential       Credential `json:"credential"`
	ProtocolID       string     `json:"protocolId"`
	HysteriaAuth     string     `json:"hysteriaAuth,omitempty"`
	HysteriaIdentity string     `json:"hysteriaIdentity,omitempty"`
}

func (m CredentialMaterial) Validate() error {
	if m.Credential.Validate() != nil {
		return errors.New("glivela: invalid credential material")
	}
	if _, err := uuid.Parse(m.ProtocolID); err != nil || Identity(m.ProtocolID) != m.Credential.Identity {
		return errors.New("glivela: credential secret does not match its identity")
	}
	if (m.HysteriaAuth == "") != (m.HysteriaIdentity == "") || m.HysteriaAuth != "" && (len(m.HysteriaAuth) > 512 || Identity(m.HysteriaAuth) != m.HysteriaIdentity) {
		return errors.New("glivela: Hysteria credential secret does not match its identity")
	}
	if m.Credential.Kind == RouteCredential && m.HysteriaAuth != "" {
		return errors.New("glivela: routed credentials cannot use Hysteria")
	}
	return nil
}

type RealityEndpoint struct {
	ID            string   `json:"id"`
	EntryID       string   `json:"entryId"`
	InboundTag    string   `json:"inboundTag"`
	ListenAddress string   `json:"listenAddress"`
	ListenPort    int      `json:"listenPort"`
	AdvertiseHost string   `json:"advertiseHost"`
	AdvertisePort int      `json:"advertisePort"`
	Target        string   `json:"target"`
	ServerNames   []string `json:"serverNames"`
	PrivateKey    string   `json:"privateKey"`
	PublicKey     string   `json:"publicKey"`
	ShortIDs      []string `json:"shortIds"`
	Fingerprint   string   `json:"fingerprint"`
}

type HysteriaEndpoint struct {
	ID             string `json:"id"`
	EntryID        string `json:"entryId"`
	InboundTag     string `json:"inboundTag"`
	ListenPort     int    `json:"listenPort"`
	AdvertiseHost  string `json:"advertiseHost"`
	AdvertisePort  int    `json:"advertisePort"`
	ServerName     string `json:"serverName"`
	CertificatePEM string `json:"certificatePem"`
	PrivateKeyPEM  string `json:"privateKeyPem"`
}

func (e HysteriaEndpoint) Validate() error {
	if e.validateSubscription() != nil || !validInboundTag(e.InboundTag) || !validPort(e.ListenPort) || len(e.CertificatePEM) > 64<<10 || len(e.PrivateKeyPEM) > 64<<10 {
		return errors.New("glivela: invalid Hysteria endpoint")
	}
	pair, err := tls.X509KeyPair([]byte(e.CertificatePEM), []byte(e.PrivateKeyPEM))
	if err != nil || len(pair.Certificate) == 0 {
		return errors.New("glivela: invalid Hysteria certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(e.ServerName) != nil {
		return errors.New("glivela: Hysteria certificate does not cover its server name")
	}
	return nil
}

func (e HysteriaEndpoint) validateSubscription() error {
	if !ValidIdentifier(e.ID) || !ValidIdentifier(e.EntryID) || !validPort(e.AdvertisePort) || !validShareHost(e.AdvertiseHost) || !validServerName(e.ServerName) {
		return errors.New("glivela: invalid Hysteria subscription endpoint")
	}
	return nil
}

func HysteriaCertificateNotAfter(endpoint HysteriaEndpoint) (time.Time, error) {
	if endpoint.Validate() != nil {
		return time.Time{}, errors.New("glivela: invalid Hysteria endpoint")
	}
	pair, _ := tls.X509KeyPair([]byte(endpoint.CertificatePEM), []byte(endpoint.PrivateKeyPEM))
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	return leaf.NotAfter.UTC(), nil
}

func (e RealityEndpoint) Validate() error {
	address, addressErr := netip.ParseAddr(e.ListenAddress)
	if e.validateSubscription() != nil || !validInboundTag(e.InboundTag) || addressErr != nil || !privateServiceIPv4(address) || address.String() != e.ListenAddress || e.ListenPort < 1024 || !validPort(e.ListenPort) || !validRealityTarget(e.Target) || strings.TrimSpace(e.PrivateKey) == "" || len(e.PrivateKey) > 256 {
		return errors.New("glivela: invalid REALITY endpoint")
	}
	return nil
}

func (e RealityEndpoint) validateSubscription() error {
	if !ValidIdentifier(e.ID) || !ValidIdentifier(e.EntryID) || !validPort(e.AdvertisePort) || !validShareHost(e.AdvertiseHost) || strings.TrimSpace(e.PublicKey) == "" || len(e.PublicKey) > 256 || len(e.ServerNames) == 0 || len(e.ServerNames) > 16 || len(e.ShortIDs) == 0 || len(e.ShortIDs) > 16 {
		return errors.New("glivela: invalid REALITY subscription endpoint")
	}
	seenNames, seenIDs := map[string]bool{}, map[string]bool{}
	for _, name := range e.ServerNames {
		if !validServerName(name) || seenNames[name] {
			return errors.New("glivela: invalid REALITY server name")
		}
		seenNames[name] = true
	}
	for _, shortID := range e.ShortIDs {
		if !validShortID(shortID) || seenIDs[shortID] {
			return errors.New("glivela: invalid REALITY short ID")
		}
		seenIDs[shortID] = true
	}
	if e.Fingerprint != "" && !ValidIdentifier(e.Fingerprint) {
		return errors.New("glivela: invalid REALITY fingerprint")
	}
	return nil
}

type RoutePeer struct {
	EgressID   string       `json:"egressId"`
	Address    string       `json:"address"`
	Port       int          `json:"port"`
	ExitFamily EgressPolicy `json:"exitFamily,omitempty"`
	Ready      bool         `json:"ready,omitempty"`
}

func (p RoutePeer) Validate() error {
	address, err := netip.ParseAddr(p.Address)
	if !ValidIdentifier(p.EgressID) || err != nil || !privateServiceIPv4(address) || !validPort(p.Port) {
		return errors.New("glivela: invalid route peer")
	}
	return nil
}

type XrayPlan struct {
	Revision          uint64               `json:"revision"`
	NativeEgress      EgressPolicy         `json:"nativeEgress,omitempty"`
	RealityEndpoints  []RealityEndpoint    `json:"realityEndpoints,omitempty"`
	HysteriaEndpoints []HysteriaEndpoint   `json:"hysteriaEndpoints,omitempty"`
	Credentials       []CredentialMaterial `json:"credentials"`
	Grants            []RouteGrant         `json:"grants"`
	Peers             []RoutePeer          `json:"peers"`
}

func RenderXrayConfiguration(plan XrayPlan) ([]byte, error) {
	projection, err := prepareXrayProjection(plan)
	if err != nil {
		return nil, err
	}
	inbounds := []any{
		map[string]any{"listen": "127.0.0.1", "port": XrayAPIListenPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}, "tag": "api"},
	}
	for _, endpoint := range projection.realityEndpoints {
		clients := make([]any, 0, len(projection.credentials[endpoint.EntryID]))
		for _, material := range projection.credentials[endpoint.EntryID] {
			clients = append(clients, map[string]any{
				"email": material.Credential.User,
				"flow":  "xtls-rprx-vision",
				"id":    material.ProtocolID,
				"level": 0,
			})
		}
		inbounds = append(inbounds, map[string]any{
			"listen":   endpoint.ListenAddress,
			"port":     endpoint.ListenPort,
			"protocol": "vless",
			"tag":      endpoint.InboundTag,
			"settings": map[string]any{"clients": clients, "decryption": "none"},
			// Restore HTTP/TLS hostnames when a client sends a resolved IP, so
			// the final SOCKS egress can resolve the destination in its own family.
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": false},
			"streamSettings": map[string]any{
				"method":      "raw",
				"rawSettings": map[string]any{"acceptProxyProtocol": true, "header": map[string]any{"type": "none"}},
				"security":    "reality",
				"realitySettings": map[string]any{
					"show": false, "xver": 0, "target": endpoint.Target,
					"serverNames": slices.Clone(endpoint.ServerNames), "privateKey": endpoint.PrivateKey,
					"minClientVer": XrayMinimumClient, "maxClientVer": "", "maxTimediff": 0,
					"shortIds": slices.Clone(endpoint.ShortIDs),
				},
			},
		})
	}
	for _, endpoint := range projection.hysteriaEndpoints {
		users := make([]any, 0, len(projection.credentials[endpoint.EntryID]))
		for _, material := range projection.credentials[endpoint.EntryID] {
			if material.Credential.Kind != NativeCredential {
				continue
			}
			users = append(users, map[string]any{
				"email": material.Credential.User,
				"auth":  material.HysteriaAuth,
				"level": 0,
			})
		}
		inbounds = append(inbounds, map[string]any{
			"listen":   "0.0.0.0",
			"port":     endpoint.ListenPort,
			"protocol": "hysteria",
			"tag":      endpoint.InboundTag,
			"settings": map[string]any{"version": 2, "users": users},
			"streamSettings": map[string]any{
				"method":   "hysteria",
				"security": "tls",
				"hysteriaSettings": map[string]any{
					"version": 2, "udpIdleTimeout": 60,
					"masquerade": map[string]any{"type": ""},
				},
				"tlsSettings": map[string]any{
					"serverName": endpoint.ServerName, "alpn": []string{"h3"}, "minVersion": "1.3",
					"certificates": []any{map[string]any{
						"certificate": strings.Split(strings.TrimSpace(endpoint.CertificatePEM), "\n"),
						"key":         strings.Split(strings.TrimSpace(endpoint.PrivateKeyPEM), "\n"),
						"usage":       "encipherment",
					}},
				},
			},
		})
	}

	outbounds := []any{nativeXrayOutbound(plan.NativeEgress)}
	rules := []any{map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"}}
	composite := false
	for _, grant := range projection.grants {
		peer := projection.peers[grant.EgressID]
		tag := routeOutboundTag(grant.ID)
		outbound := map[string]any{
			"protocol": "socks", "tag": tag,
			"settings": map[string]any{"servers": []any{map[string]any{"address": peer.Address, "port": peer.Port}}},
		}
		if grant.IPv4EgressID != "" {
			composite = true
			outbound["targetStrategy"] = "ForceIPv6"
			ipv4 := projection.peers[grant.IPv4EgressID]
			outbounds = append(outbounds, outbound, map[string]any{
				"protocol": "socks", "tag": tag + "-ipv4", "targetStrategy": "ForceIPv4",
				"settings": map[string]any{"servers": []any{map[string]any{"address": ipv4.Address, "port": ipv4.Port}}},
			})
			rules = append(rules, compositeXrayRules(grant)...)
			continue
		}
		outbounds = append(outbounds, outbound)
		scope := func(network, outbound string) map[string]any {
			return map[string]any{"type": "field", "inboundTag": []string{grant.InboundTag}, "user": []string{grant.Route.User}, "network": network, "outboundTag": outbound}
		}
		rules = append(rules,
			scope("udp", "blocked"),
			scope("tcp", tag),
			map[string]any{"type": "field", "user": []string{grant.Route.User}, "outboundTag": "blocked"},
		)
	}
	outbounds = append(outbounds, map[string]any{"protocol": "blackhole", "tag": "blocked", "settings": map[string]any{}})
	config := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"api":       map[string]any{"tag": "api", "services": []string{"HandlerService", "LoggerService", "StatsService"}},
		"stats":     map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		"routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": rules},
	}
	if composite {
		config["routing"] = map[string]any{"domainStrategy": "IPOnDemand", "rules": rules}
		// Local DoH bypasses proxy routing and control-plane DNS. Xray owns
		// resolution and caching; no Agent-side resolver or scripts are needed.
		config["dns"] = map[string]any{
			"queryStrategy": "UseIP",
			"servers":       []string{"https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"},
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, errors.New("glivela: cannot encode Xray configuration")
	}
	return encoded, nil
}

func LinkForCredential(endpoint RealityEndpoint, material CredentialMaterial, name string) (string, error) {
	if endpoint.validateSubscription() != nil || material.Validate() != nil || material.Credential.EntryID != endpoint.EntryID || !validDisplayName(name) {
		return "", errors.New("glivela: invalid subscription link input")
	}
	fingerprint := endpoint.Fingerprint
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	query := []string{
		"encryption=none",
		"flow=xtls-rprx-vision",
		"fp=" + fingerprint,
		"pbk=" + endpoint.PublicKey,
		"security=reality",
		"sid=" + endpoint.ShortIDs[0],
		"sni=" + endpoint.ServerNames[0],
		"spx=%2F",
		"type=tcp",
	}
	return "vless://" + material.ProtocolID + "@" + net.JoinHostPort(endpoint.AdvertiseHost, strconv.Itoa(endpoint.AdvertisePort)) + "?" + strings.Join(query, "&") + "#" + escapeLinkFragment(name), nil
}

func Hysteria2LinkForCredential(endpoint HysteriaEndpoint, material CredentialMaterial, name string) (string, error) {
	if endpoint.validateSubscription() != nil || material.Validate() != nil || material.Credential.EntryID != endpoint.EntryID || material.HysteriaAuth == "" || !validDisplayName(name) {
		return "", errors.New("glivela: invalid Hysteria subscription link input")
	}
	link := url.URL{
		Scheme:   "hysteria2",
		User:     url.User(material.HysteriaAuth),
		Host:     net.JoinHostPort(endpoint.AdvertiseHost, strconv.Itoa(endpoint.AdvertisePort)),
		Fragment: name,
	}
	link.RawQuery = url.Values{"sni": {endpoint.ServerName}, "alpn": {"h3"}}.Encode()
	return link.String(), nil
}

type xrayProjection struct {
	realityEndpoints  []RealityEndpoint
	hysteriaEndpoints []HysteriaEndpoint
	credentials       map[string][]CredentialMaterial
	grants            []RouteGrant
	peers             map[string]RoutePeer
}

func prepareXrayProjection(plan XrayPlan) (xrayProjection, error) {
	if err := plan.NativeEgress.Validate(); err != nil {
		return xrayProjection{}, err
	}
	if plan.Revision == 0 || len(plan.RealityEndpoints)+len(plan.HysteriaEndpoints) == 0 || len(plan.RealityEndpoints)+len(plan.HysteriaEndpoints) > 256 || len(plan.Credentials) > 65536 || len(plan.Grants) > 65536 || len(plan.Peers) > 1024 {
		return xrayProjection{}, errors.New("glivela: invalid Xray plan")
	}
	projection := xrayProjection{credentials: map[string][]CredentialMaterial{}, peers: map[string]RoutePeer{}}
	entryTags, routeTags, tags, ports := map[string][]string{}, map[string]string{}, map[string]bool{}, map[string]bool{}
	projection.realityEndpoints = slices.Clone(plan.RealityEndpoints)
	slices.SortFunc(projection.realityEndpoints, func(a, b RealityEndpoint) int { return strings.Compare(a.EntryID, b.EntryID) })
	for _, endpoint := range projection.realityEndpoints {
		portKey := "tcp/" + strconv.Itoa(endpoint.ListenPort)
		if endpoint.Validate() != nil || tags[endpoint.InboundTag] || ports[portKey] || endpoint.ListenPort == XrayAPIListenPort {
			return xrayProjection{}, errors.New("glivela: conflicting Xray endpoint")
		}
		entryTags[endpoint.EntryID] = append(entryTags[endpoint.EntryID], endpoint.InboundTag)
		if routeTags[endpoint.EntryID] != "" {
			return xrayProjection{}, errors.New("glivela: multiple routable inbounds share one entry")
		}
		routeTags[endpoint.EntryID] = endpoint.InboundTag
		tags[endpoint.InboundTag], ports[portKey] = true, true
	}
	projection.hysteriaEndpoints = slices.Clone(plan.HysteriaEndpoints)
	slices.SortFunc(projection.hysteriaEndpoints, func(a, b HysteriaEndpoint) int { return strings.Compare(a.EntryID, b.EntryID) })
	for _, endpoint := range projection.hysteriaEndpoints {
		portKey := "udp/" + strconv.Itoa(endpoint.ListenPort)
		if endpoint.Validate() != nil || tags[endpoint.InboundTag] || ports[portKey] || endpoint.ListenPort == XrayAPIListenPort {
			return xrayProjection{}, errors.New("glivela: conflicting Xray endpoint")
		}
		entryTags[endpoint.EntryID] = append(entryTags[endpoint.EntryID], endpoint.InboundTag)
		tags[endpoint.InboundTag], ports[portKey] = true, true
	}
	for _, peer := range plan.Peers {
		if peer.Validate() != nil || projection.peers[peer.EgressID].EgressID != "" {
			return xrayProjection{}, errors.New("glivela: conflicting route peer")
		}
		projection.peers[peer.EgressID] = peer
	}
	materialByID := map[string]CredentialMaterial{}
	users, identities, hysteriaIdentities := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, material := range plan.Credentials {
		credential := material.Credential
		if material.Validate() != nil || len(entryTags[credential.EntryID]) == 0 || materialByID[credential.ID].Credential.ID != "" || users[credential.User] || identities[credential.Identity] || material.HysteriaIdentity != "" && hysteriaIdentities[material.HysteriaIdentity] {
			return xrayProjection{}, errors.New("glivela: conflicting Xray credential")
		}
		materialByID[credential.ID], users[credential.User], identities[credential.Identity] = material, true, true
		if material.HysteriaIdentity != "" {
			hysteriaIdentities[material.HysteriaIdentity] = true
		}
		if credential.Enabled {
			if credential.Kind == NativeCredential && slices.ContainsFunc(projection.hysteriaEndpoints, func(endpoint HysteriaEndpoint) bool { return endpoint.EntryID == credential.EntryID }) && material.HysteriaAuth == "" {
				return xrayProjection{}, errors.New("glivela: Hysteria endpoint credential is incomplete")
			}
			projection.credentials[credential.EntryID] = append(projection.credentials[credential.EntryID], material)
		}
	}
	for entryID := range projection.credentials {
		slices.SortFunc(projection.credentials[entryID], func(a, b CredentialMaterial) int { return strings.Compare(a.Credential.ID, b.Credential.ID) })
	}
	grants := slices.Clone(plan.Grants)
	slices.SortFunc(grants, func(a, b RouteGrant) int { return strings.Compare(a.ID, b.ID) })
	seenGrants, usedRoutes := map[string]bool{}, map[string]bool{}
	for _, grant := range grants {
		base, hasBase := materialByID[grant.Base.ID]
		route, hasRoute := materialByID[grant.Route.ID]
		peer, hasPeer := projection.peers[grant.EgressID]
		if grant.Validate() != nil || seenGrants[grant.ID] || !hasBase || !hasRoute || base.Credential != grant.Base || route.Credential != grant.Route || usedRoutes[grant.Route.ID] || !hasPeer || peer.EgressID != grant.EgressID || routeTags[grant.EntryID] != grant.InboundTag || !grant.Deployable() && route.Credential.Enabled {
			return xrayProjection{}, errors.New("glivela: conflicting Xray route grant")
		}
		seenGrants[grant.ID], usedRoutes[grant.Route.ID] = true, true
		if grant.Deployable() {
			projection.grants = append(projection.grants, grant)
		}
		if grant.IPv4EgressID != "" {
			secondary := projection.peers[grant.IPv4EgressID]
			if err := ValidateCompositePeers(grant, peer, secondary); err != nil {
				return xrayProjection{}, err
			}
			for _, endpoint := range projection.realityEndpoints {
				if endpoint.InboundTag == grant.InboundTag && (endpoint.ListenAddress == peer.Address || endpoint.ListenAddress == secondary.Address) {
					return xrayProjection{}, errors.New("glivela: composite landing transport is the entry machine")
				}
			}
		}
	}
	for _, material := range plan.Credentials {
		if material.Credential.Kind == RouteCredential && material.Credential.Enabled && !usedRoutes[material.Credential.ID] {
			return xrayProjection{}, errors.New("glivela: orphaned routed credential")
		}
	}
	return projection, nil
}

func routeOutboundTag(grantID string) string {
	return "meridian-route-" + Identity(grantID)[:32]
}

func validPort(port int) bool { return port > 0 && port <= 65535 }

func privateServiceIPv4(address netip.Addr) bool {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return address.Is4() && (address.IsPrivate() || cgnat.Contains(address))
}

func validRealityTarget(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || !validShareHost(host) {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && validPort(number)
}

func validShareHost(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/?#@\x00\r\n") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	return validServerName(value)
}

func validServerName(value string) bool {
	if value == "" || len(value) > 253 || strings.Trim(value, ".") != value {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validShortID(value string) bool {
	if len(value) > 16 || len(value)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func escapeLinkFragment(value string) string {
	replacer := strings.NewReplacer("%", "%25", "#", "%23", "?", "%3F", " ", "%20")
	return replacer.Replace(value)
}
