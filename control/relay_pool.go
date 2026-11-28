package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"maps"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

type RelayPoolChange struct {
	Pool             glivela.RelayPool `json:"pool"`
	ExpectedRevision uint64            `json:"expectedRevision,string"`
	Delete           bool              `json:"delete,omitempty"`
}

type RelayPoolRevocationStatus struct {
	PendingEntries  []string `json:"pendingEntries"`
	PendingLandings []string `json:"pendingLandings"`
	Complete        bool     `json:"complete"`
}

type RelayPoolChangeResult struct {
	PoolID     string                    `json:"poolId"`
	Revision   uint64                    `json:"revision,string"`
	Deleted    bool                      `json:"deleted,omitempty"`
	Revocation RelayPoolRevocationStatus `json:"revocation"`
}

type RelayPoolMemberView struct {
	NodeID        string    `json:"nodeId"`
	CertificateID string    `json:"certificateId"`
	IngressIPv4   string    `json:"ingressIpv4,omitempty"`
	IngressIPv6   string    `json:"ingressIpv6,omitempty"`
	EgressIPv4    string    `json:"egressIpv4,omitempty"`
	EgressIPv6    string    `json:"egressIpv6,omitempty"`
	Drained       bool      `json:"drained"`
	DrainReason   string    `json:"drainReason,omitempty"`
	DrainResumeAt time.Time `json:"drainResumeAt,omitempty"`
	NodeSuspended bool      `json:"nodeSuspended"`
	RuntimeReady  bool      `json:"runtimeReady"`
}

type RelayPoolView struct {
	ID         string                    `json:"id"`
	Name       string                    `json:"name"`
	Revision   uint64                    `json:"revision,string"`
	Strategy   glivela.RelayPoolStrategy `json:"strategy"`
	Members    []RelayPoolMemberView     `json:"members"`
	RouteIDs   []string                  `json:"routeIds"`
	Revocation RelayPoolRevocationStatus `json:"revocation"`
}

type EntryRelayConfigChange struct {
	EntryID                string                   `json:"entryId"`
	ExpectedRevision       uint64                   `json:"expectedRevision,string"`
	ExpectedConfigRevision *uint64                  `json:"expectedConfigRevision,string,omitempty"`
	Config                 glivela.EntryRelayConfig `json:"config"`
}

type EntryRelayConfigView struct {
	EntryID        string                   `json:"entryId"`
	Revision       uint64                   `json:"revision,string"`
	ConfigRevision uint64                   `json:"configRevision,string"`
	Config         glivela.EntryRelayConfig `json:"config"`
}

func randomSS2022Key16() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	defer clear(raw[:])
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

func relayEdgeCredentialID(entryID, accountID, relayNodeID, entrySrc, relayIngress, relayEgress string, udp bool) string {
	mode := "tcp"
	if udp {
		mode = "udp"
	}
	sum := sha256.Sum256([]byte("relay-edge\x00" + entryID + "\x00" + accountID + "\x00" + relayNodeID + "\x00" + entrySrc + "\x00" + relayIngress + "\x00" + relayEgress + "\x00" + mode))
	return "re-" + hex.EncodeToString(sum[:12])
}

func landingHopCredentialID(entryID, accountID, relayNodeID, relayEgress, egressID, landingAddress, egressIP string, udp bool) string {
	mode := "tcp"
	if udp {
		mode = "udp"
	}
	sum := sha256.Sum256([]byte("landing-hop\x00" + entryID + "\x00" + accountID + "\x00" + relayNodeID + "\x00" + relayEgress + "\x00" + egressID + "\x00" + landingAddress + "\x00" + egressIP + "\x00" + mode))
	return "lh-" + hex.EncodeToString(sum[:12])
}

func twoHopEIHCredentialID(entryID, egressID, landingAddress, source, egressIP string, udp bool) string {
	mode := "tcp"
	if udp {
		mode = "udp"
	}
	sum := sha256.Sum256([]byte("twohop-eih\x00" + entryID + "\x00" + egressID + "\x00" + landingAddress + "\x00" + source + "\x00" + egressIP + "\x00" + mode))
	return "th-" + hex.EncodeToString(sum[:12])
}

func twoHopEIHBindingID(entryID, egressID, landingAddress, serverTransportID string) string {
	sum := sha256.Sum256([]byte("twohop-bind\x00" + entryID + "\x00" + egressID + "\x00" + landingAddress + "\x00" + serverTransportID))
	return "thb-" + hex.EncodeToString(sum[:12])
}

func eihUserEmail(credID string) string {
	return "eih-" + credID
}

func ensureNodeEIHKey(m *glivela.ImportMaterial, node Node) (string, error) {
	if existing, ok := m.EIHNodeKeys[node.ID]; ok {
		if existing.CertificateID != node.CertificateID {
			return "", errors.New("control: EIH node server key certificate mismatch")
		}
		return existing.ServerKey, nil
	}
	secret, err := randomSS2022Key16()
	if err != nil {
		return "", err
	}
	m.EIHNodeKeys = maps.Clone(m.EIHNodeKeys)
	if m.EIHNodeKeys == nil {
		m.EIHNodeKeys = map[string]glivela.EIHNodeKey{}
	}
	m.EIHNodeKeys[node.ID] = glivela.EIHNodeKey{
		NodeID:        node.ID,
		CertificateID: node.CertificateID,
		ServerKey:     secret,
	}
	return secret, nil
}

func ensureRelayPoolCredential(m *glivela.ImportMaterial, credID string) (string, error) {
	if existing := m.RelayPoolCredentials[credID]; existing != "" {
		return existing, nil
	}
	secret, err := randomSS2022Key16()
	if err != nil {
		return "", err
	}
	m.RelayPoolCredentials = maps.Clone(m.RelayPoolCredentials)
	if m.RelayPoolCredentials == nil {
		m.RelayPoolCredentials = map[string]string{}
	}
	m.RelayPoolCredentials[credID] = secret
	return secret, nil
}

func socketOccupiedBySingleUser(plan landing.Plan, address string) bool {
	if plan.HasServerListener() && plan.Transport.Endpoint(plan.Address) == address && plan.Transport.ListenerPort() == glivela.RelayPoolPort {
		return true
	}
	for _, c := range plan.ActiveClientListeners() {
		cAddr := plan.Transport.PublicAddress
		if c.Transport == "ipv6-ss2022" || c.Interface != "" {
			cAddr = c.Address
		}
		if cAddr == address && c.Port == glivela.RelayPoolPort {
			return true
		}
	}
	return false
}

func resolveRelayMemberHops(entry Node, cfg glivela.EntryRelayConfig, member glivela.RelayPoolMember, pr glivela.PooledRoute) (entrySrc, relayIngress, ingressFamily, relayEgress, egressFamily string, ok bool) {
	if entry.Desired.Entry == nil || member.NodeID == pr.EntryID || member.NodeID == pr.EgressID {
		return "", "", "", "", "", false
	}
	if strings.Contains(pr.LandingAddress, ":") {
		egressFamily, relayEgress = "ipv6", member.EgressIPv6
	} else {
		egressFamily, relayEgress = "ipv4", member.EgressIPv4
	}
	if relayEgress == "" || relayEgress == pr.LandingAddress {
		return "", "", "", "", "", false
	}
	allowV4 := entry.Desired.Entry.NativeEgress != glivela.EgressIPv6Only && (pr.IngressFamily == "" || pr.IngressFamily == "ipv4")
	allowV6 := entry.Desired.Entry.NativeEgress != glivela.EgressIPv4Only && (pr.IngressFamily == "" || pr.IngressFamily == "ipv6")
	if allowV6 && cfg.SourceIPv6 != "" && member.IngressIPv6 != "" && cfg.SourceIPv6 != member.IngressIPv6 {
		return cfg.SourceIPv6, member.IngressIPv6, "ipv6", relayEgress, egressFamily, true
	}
	if allowV4 && cfg.SourceIPv4 != "" && member.IngressIPv4 != "" && cfg.SourceIPv4 != member.IngressIPv4 {
		return cfg.SourceIPv4, member.IngressIPv4, "ipv4", relayEgress, egressFamily, true
	}
	return "", "", "", "", "", false
}

func entryEffectiveRelayConfig(entry Node, m glivela.ImportMaterial) glivela.EntryRelayConfig {
	cfg := m.EntryRelayConfigs[entry.ID]
	if entry.Desired.Entry != nil && len(entry.Desired.Entry.RealityEndpoints) > 0 {
		ep := entry.Desired.Entry.RealityEndpoints[0]
		if cfg.SourceIPv6 == "" && glivela.PublicTransportIPv6(ep.ListenAddress) {
			cfg.SourceIPv6 = ep.ListenAddress
		}
		if cfg.SourceIPv4 == "" && glivela.PublicTransportIPv4(ep.IPv4ListenAddress) {
			cfg.SourceIPv4 = ep.IPv4ListenAddress
		}
	}
	return cfg
}

// ensurePooledRouteCredentials populates deterministic EIH server-iPSK and uPSK
// credentials for every configured pooled route and compatible pool member.
func ensurePooledRouteCredentials(nodes map[string]Node, m *glivela.ImportMaterial) error {
	if m.ServerTransportVersion != glivela.CurrentServerTransportVersion {
		return nil
	}
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	grantsByID := map[string]glivela.RouteGrant{}
	for _, a := range m.Plan.Accounts {
		for _, g := range a.Grants {
			if !m.DeletedRoutes[g.ID] && (g.RelayPoolID != "" || m.PooledRoutes[g.ID].PendingLegacyCutover) {
				grantsByID[g.ID] = g
			}
		}
	}
	routeIDs := make([]string, 0, len(m.PooledRoutes))
	for id := range m.PooledRoutes {
		routeIDs = append(routeIDs, id)
	}
	slices.Sort(routeIDs)
	for _, grantID := range routeIDs {
		pr := m.PooledRoutes[grantID]
		g, ok := grantsByID[grantID]
		if !ok {
			continue
		}
		entry, hasEntry := byID[pr.EntryID]
		target, hasTarget := byID[pr.EgressID]
		pool, hasPool := m.RelayPools[pr.RelayPoolID]
		if !hasEntry || entry.Desired.Entry == nil || !hasTarget || target.Desired.Landing == nil || !hasPool {
			continue
		}
		if _, err := ensureNodeEIHKey(m, target); err != nil {
			return err
		}
		cfg := entryEffectiveRelayConfig(entry, *m)
		for _, member := range pool.Members {
			relay, hasRelay := byID[member.NodeID]
			if !hasRelay || relay.Desired.Landing == nil || relay.CertificateID != member.CertificateID {
				continue
			}
			entrySrc, relayIngress, _, relayEgress, _, compat := resolveRelayMemberHops(entry, cfg, member, pr)
			if !compat {
				continue
			}
			if _, err := ensureNodeEIHKey(m, relay); err != nil {
				return err
			}
			edgeID := relayEdgeCredentialID(pr.EntryID, pr.AccountID, member.NodeID, entrySrc, relayIngress, relayEgress, g.UDP)
			if _, err := ensureRelayPoolCredential(m, edgeID); err != nil {
				return err
			}
			hopID := landingHopCredentialID(pr.EntryID, pr.AccountID, member.NodeID, relayEgress, pr.EgressID, pr.LandingAddress, pr.EgressIP, g.UDP)
			if _, err := ensureRelayPoolCredential(m, hopID); err != nil {
				return err
			}
		}
	}
	return nil
}

// twoHopEIHBindingReferenced reports whether any non-deleted grant, retiring
// legacy three-hop transition, or active cutover still references this EIH binding.
func twoHopEIHBindingReferenced(m glivela.ImportMaterial, b glivela.TwoHopEIHBinding, cutovers map[string]SocketCutover) bool {
	for _, c := range cutovers {
		for _, consumer := range c.Consumers {
			if consumer.BindingID == b.ID {
				return true
			}
		}
	}
	for _, a := range m.Plan.Accounts {
		for _, g := range a.Grants {
			if m.DeletedRoutes[g.ID] || g.EntryID != b.EntryID {
				continue
			}
			if b.ServerTransport != "" {
				r, ok := m.ServerTransports[b.ServerTransport]
				if !ok || r.AccountID != g.AccountID || r.EntryID != g.EntryID || r.EgressID != g.EgressID || g.EgressID != b.EgressID {
					continue
				}
				if g.RelayPoolID == "" && g.ClientChainID == r.Peer.ClientChainID {
					return true
				}
				if r.Peer.Relay != nil && g.RelayPoolID != "" {
					if pr, ok := m.PooledRoutes[g.ID]; ok && pr.RetiringLegacyTransport && pr.LegacyTransportID == r.ID {
						return true
					}
				}
			} else if g.RelayPoolID == "" && g.ClientChainID == "" && (g.EgressID == b.EgressID || g.IPv4EgressID == b.EgressID) {
				return true
			}
		}
	}
	return false
}

// twoHopEIHBindingActive computes live EIH user activation and UDP permission
// strictly from currently enabled grants (including a cut-over legacy three-hop
// landing retained until the entry confirms its RelayPool receipt) so disabling
// a grant or revoking UDP takes effect immediately, even mid-cutover.
func twoHopEIHBindingActive(nodes map[string]Node, m glivela.ImportMaterial, grants map[string]glivela.RouteGrant, b glivela.TwoHopEIHBinding, now time.Time) (active bool, udp bool) {
	foundEntry := false
	for _, n := range nodes {
		if n.ID == b.EntryID && n.Desired.Entry != nil && !entryRetired(m, n.ID) {
			foundEntry = true
			break
		}
	}
	if !foundEntry {
		return false, false
	}
	for _, g := range grants {
		if m.DeletedRoutes[g.ID] || !g.Enabled || !g.Route.Enabled || g.EntryID != b.EntryID {
			continue
		}
		if b.ServerTransport != "" {
			r, ok := m.ServerTransports[b.ServerTransport]
			if !ok || r.AccountID != g.AccountID || r.EntryID != g.EntryID || r.EgressID != g.EgressID || g.EgressID != b.EgressID {
				continue
			}
			matched := g.RelayPoolID == "" && g.ClientChainID == r.Peer.ClientChainID
			if !matched && r.Peer.Relay != nil && g.RelayPoolID != "" {
				if pr, ok := m.PooledRoutes[g.ID]; ok && pr.RetiringLegacyTransport && pr.LegacyTransportID == r.ID && isRetainedLegacyThreeHop(nodes, m, r.ID, now) {
					matched = true
				}
			}
			if !matched {
				continue
			}
			active = true
			if g.UDP {
				udp = true
			}
		} else if g.RelayPoolID == "" && g.ClientChainID == "" && (g.EgressID == b.EgressID || g.IPv4EgressID == b.EgressID) {
			active = true
			if g.UDP {
				udp = true
			}
		}
	}
	return active, udp
}

// pruneUnreferencedTwoHopEIHBindings deletes a TwoHopEIHBinding only after no
// non-deleted grant or active cutover references it AND the affected landing
// has confirmed a fresh receipt without that EIH user.
func pruneUnreferencedTwoHopEIHBindings(m *glivela.ImportMaterial, nodes map[string]Node, cutovers map[string]SocketCutover, now time.Time) {
	if len(m.TwoHopEIHBindings) == 0 {
		return
	}
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	next := maps.Clone(m.TwoHopEIHBindings)
	for id, b := range m.TwoHopEIHBindings {
		if twoHopEIHBindingReferenced(*m, b, cutovers) {
			continue
		}
		target, ok := byID[b.EgressID]
		if ok && target.Desired.Landing != nil {
			stillPresent := false
			for _, l := range target.Desired.Landing.EIHListeners {
				for _, u := range l.Users {
					if u.ID == b.CredentialID {
						stillPresent = true
					}
				}
			}
			if stillPresent || !runtimeFresh(target, now) {
				continue
			}
		}
		delete(next, id)
	}
	if len(next) == 0 {
		m.TwoHopEIHBindings = nil
	} else {
		m.TwoHopEIHBindings = next
	}
}

// gcUnreferencedRelayPoolCredentials deletes only uPSK credentials and node
// server keys that are no longer referenced by any pooled route, pool member,
// two-hop EIH binding, or in-flight socket cutover.
func gcUnreferencedRelayPoolCredentials(m *glivela.ImportMaterial, nodes map[string]Node, cutovers map[string]SocketCutover) {
	if m.ServerTransportVersion != glivela.CurrentServerTransportVersion {
		return
	}
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	grantsByID := map[string]glivela.RouteGrant{}
	for _, a := range m.Plan.Accounts {
		for _, g := range a.Grants {
			if !m.DeletedRoutes[g.ID] && (g.RelayPoolID != "" || m.PooledRoutes[g.ID].PendingLegacyCutover) {
				grantsByID[g.ID] = g
			}
		}
	}
	usedCreds := map[string]bool{}
	usedNodes := map[string]bool{}
	for grantID, pr := range m.PooledRoutes {
		g, ok := grantsByID[grantID]
		if !ok {
			continue
		}
		usedNodes[pr.EgressID] = true
		entry, hasEntry := byID[pr.EntryID]
		pool, hasPool := m.RelayPools[pr.RelayPoolID]
		if !hasEntry || entry.Desired.Entry == nil || !hasPool {
			continue
		}
		cfg := entryEffectiveRelayConfig(entry, *m)
		for _, member := range pool.Members {
			usedNodes[member.NodeID] = true
			entrySrc, relayIngress, _, relayEgress, _, compat := resolveRelayMemberHops(entry, cfg, member, pr)
			if !compat {
				continue
			}
			usedCreds[relayEdgeCredentialID(pr.EntryID, pr.AccountID, member.NodeID, entrySrc, relayIngress, relayEgress, g.UDP)] = true
			usedCreds[landingHopCredentialID(pr.EntryID, pr.AccountID, member.NodeID, relayEgress, pr.EgressID, pr.LandingAddress, pr.EgressIP, g.UDP)] = true
		}
	}
	for _, b := range m.TwoHopEIHBindings {
		usedNodes[b.EgressID] = true
		usedCreds[b.CredentialID] = true
	}
	for _, c := range cutovers {
		usedNodes[c.TargetNodeID] = true
		for _, consumer := range c.Consumers {
			if consumer.CredentialID != "" {
				usedCreds[consumer.CredentialID] = true
			}
		}
	}
	if len(m.RelayPoolCredentials) > 0 {
		nextCreds := make(map[string]string, len(usedCreds))
		for id, secret := range m.RelayPoolCredentials {
			if usedCreds[id] {
				nextCreds[id] = secret
			}
		}
		if len(nextCreds) == 0 {
			m.RelayPoolCredentials = nil
		} else {
			m.RelayPoolCredentials = nextCreds
		}
	}
	if len(m.EIHNodeKeys) > 0 {
		nextKeys := make(map[string]glivela.EIHNodeKey, len(usedNodes))
		for id, key := range m.EIHNodeKeys {
			if usedNodes[id] {
				nextKeys[id] = key
			}
		}
		if len(nextKeys) == 0 {
			m.EIHNodeKeys = nil
		} else {
			m.EIHNodeKeys = nextKeys
		}
	}
}

func hasEIHUser(plan landing.Plan, address string, want landing.EIHUser) bool {
	for _, l := range plan.EIHListeners {
		if l.Address != address || l.Port != glivela.RelayPoolPort {
			continue
		}
		for _, u := range l.Users {
			if reflect.DeepEqual(u, want) {
				return true
			}
		}
	}
	return false
}

func nodeHasAppliedEIHUser(node Node, certID, address string, want landing.EIHUser, now time.Time) bool {
	if node.Desired.Landing == nil || node.CertificateID != certID || !runtimeFresh(node, now) || node.Receipt == nil || node.Receipt.ManagementIdentity == nil || node.Receipt.ManagementIdentity.Address != node.Desired.Landing.Address {
		return false
	}
	return hasEIHUser(*node.Desired.Landing, address, want)
}

func entryHasActiveCandidate(entry Node, poolKey string, cand glivela.EntryPoolCandidate, edge glivela.EntryRelayEdge) bool {
	if entry.Desired.Entry == nil {
		return false
	}
	hasEdge := false
	for _, existing := range entry.Desired.Entry.RelayEdges {
		if existing == edge {
			hasEdge = true
			break
		}
	}
	if !hasEdge {
		return false
	}
	for _, existingPool := range entry.Desired.Entry.RelayPools {
		if existingPool.Key != poolKey {
			continue
		}
		for _, existingCand := range existingPool.Candidates {
			if existingCand == cand {
				return true
			}
		}
	}
	return false
}

func activeListenerCutoverBlocked(cutovers map[string]SocketCutover, nodeID, address string) bool {
	for _, c := range cutovers {
		if c.TargetNodeID == nodeID && c.Address == address && (c.Phase == "starting" || c.Phase == "listener-pending" || c.Phase == "rollback-applying" || c.Phase == "rollback-pending") {
			return true
		}
	}
	return false
}

func cutoverOwnsSocket(cutovers map[string]SocketCutover, nodeID, address string) bool {
	for _, c := range cutovers {
		if c.TargetNodeID == nodeID && c.Address == address && (c.Phase == "listener-pending" || c.Phase == "entries-applying" || c.Phase == "entries-pending") {
			return true
		}
	}
	return false
}

func hasAnyPoolOrEIHState(nodes map[string]Node) bool {
	for _, n := range nodes {
		if n.Desired.Landing != nil && len(n.Desired.Landing.EIHListeners) > 0 {
			return true
		}
		if n.Desired.Entry != nil && (len(n.Desired.Entry.RelayPools) > 0 || len(n.Desired.Entry.RelayEdges) > 0 || n.Desired.Entry.Observatory != nil) {
			return true
		}
	}
	return false
}

// projectRelayPools reconciles single-port 24000 EIH listeners on relays and
// landings and projects RelayPool balancers, deduplicated physical edges, and
// entry-level burstObservatory configuration onto enrolled entries.
func projectRelayPools(nodes map[string]Node, m glivela.ImportMaterial, now time.Time, isSuspended func(string) bool, cutovers map[string]SocketCutover) (bool, error) {
	if m.ServerTransportVersion != glivela.CurrentServerTransportVersion {
		return false, nil
	}
	if len(m.RelayPools) == 0 && len(m.PooledRoutes) == 0 && len(m.TwoHopEIHBindings) == 0 && len(m.EntryRelayConfigs) == 0 && !hasAnyPoolOrEIHState(nodes) {
		return false, nil
	}
	if isSuspended == nil {
		isSuspended = func(string) bool { return false }
	}
	_, serverGrants, err := effectiveBusinessCredentials(m, now)
	if err != nil {
		return false, err
	}
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	// Stage 1: Build desired EIHListener sets for every landing/relay node.
	type eihKey struct{ nodeID, address string }
	relayUsers := map[eihKey]map[string]*landing.EIHUser{}
	landingUsers := map[eihKey]map[string]landing.EIHUser{}
	addRelayTarget := func(nodeID, address string, base landing.EIHUser, target landing.EIHRelayTarget) {
		k := eihKey{nodeID, address}
		if relayUsers[k] == nil {
			relayUsers[k] = map[string]*landing.EIHUser{}
		}
		u := relayUsers[k][base.ID]
		if u == nil {
			copyUser := base
			copyUser.RelayTargets = nil
			u = &copyUser
			relayUsers[k][base.ID] = u
		}
		if !slices.Contains(u.RelayTargets, target) {
			u.RelayTargets = append(u.RelayTargets, target)
		}
	}
	addLandingUser := func(nodeID, address string, u landing.EIHUser) error {
		k := eihKey{nodeID, address}
		if landingUsers[k] == nil {
			landingUsers[k] = map[string]landing.EIHUser{}
		}
		if existing, ok := landingUsers[k][u.ID]; ok && !reflect.DeepEqual(existing, u) {
			return errors.New("control: conflicting landing EIH user policy")
		}
		landingUsers[k][u.ID] = u
		return nil
	}

	// Project migrated two-hop EIH bindings dynamically from live enabled grants
	// or active cutover windows so disabling a route or revoking UDP takes effect.
	bindingIDs := make([]string, 0, len(m.TwoHopEIHBindings))
	for id := range m.TwoHopEIHBindings {
		bindingIDs = append(bindingIDs, id)
	}
	slices.Sort(bindingIDs)
	for _, id := range bindingIDs {
		b := m.TwoHopEIHBindings[id]
		active, udp := twoHopEIHBindingActive(nodes, m, serverGrants, b, now)
		if !active {
			continue
		}
		secret := m.RelayPoolCredentials[b.CredentialID]
		if secret == "" {
			return false, errors.New("control: missing two-hop EIH credential")
		}
		if err := addLandingUser(b.EgressID, b.LandingAddress, landing.EIHUser{
			ID:       b.CredentialID,
			Email:    eihUserEmail(b.CredentialID),
			Key:      secret,
			Source:   b.Source,
			Role:     "landing",
			UDP:      udp,
			EgressIP: b.EgressIP,
		}); err != nil {
			return false, err
		}
	}

	// Compute relay & landing EIH users for all active pooled grants (including
	// PendingLegacyCutover routes so downstream EIH 24000 receipts can be gathered
	// before switching the live entry away from its legacy three-hop path).
	routeIDs := make([]string, 0, len(m.PooledRoutes))
	for id := range m.PooledRoutes {
		routeIDs = append(routeIDs, id)
	}
	slices.Sort(routeIDs)
	type plannedCandidate struct {
		relayNodeID    string
		relayCertID    string
		entrySrc       string
		relayIngress   string
		edgeID         string
		edgeKey        string
		landingAddress string
		landingKey     string
		relayUser      landing.EIHUser
		landingUser    landing.EIHUser
	}
	routeCandidates := map[string][]plannedCandidate{}
	for _, grantID := range routeIDs {
		pr := m.PooledRoutes[grantID]
		g, ok := serverGrants[grantID]
		if !ok || m.DeletedRoutes[grantID] || !g.Enabled || !g.Route.Enabled || entryRetired(m, pr.EntryID) || entryRetired(m, pr.EgressID) {
			continue
		}
		entry, hasEntry := byID[pr.EntryID]
		target, hasTarget := byID[pr.EgressID]
		pool, hasPool := m.RelayPools[pr.RelayPoolID]
		if !hasEntry || entry.Desired.Entry == nil || !hasTarget || target.Desired.Landing == nil || target.CertificateID != pr.LandingCertificateID || !hasPool {
			continue
		}
		targetKey, hasTargetKey := m.EIHNodeKeys[pr.EgressID]
		if !hasTargetKey || targetKey.CertificateID != target.CertificateID {
			continue
		}
		cfg := entryEffectiveRelayConfig(entry, m)
		for _, member := range pool.Members {
			if member.IsDrained(now) || isSuspended(member.NodeID) || entryRetired(m, member.NodeID) {
				continue
			}
			relay, hasRelay := byID[member.NodeID]
			if !hasRelay || relay.Desired.Landing == nil || relay.CertificateID != member.CertificateID {
				continue
			}
			relayKey, hasRelayKey := m.EIHNodeKeys[member.NodeID]
			if !hasRelayKey || relayKey.CertificateID != relay.CertificateID {
				continue
			}
			entrySrc, relayIngress, _, relayEgress, _, compat := resolveRelayMemberHops(entry, cfg, member, pr)
			if !compat {
				continue
			}
			edgeCredID := relayEdgeCredentialID(pr.EntryID, pr.AccountID, member.NodeID, entrySrc, relayIngress, relayEgress, g.UDP)
			hopCredID := landingHopCredentialID(pr.EntryID, pr.AccountID, member.NodeID, relayEgress, pr.EgressID, pr.LandingAddress, pr.EgressIP, g.UDP)
			edgeSecret := m.RelayPoolCredentials[edgeCredID]
			hopSecret := m.RelayPoolCredentials[hopCredID]
			if edgeSecret == "" || hopSecret == "" {
				continue
			}
			relayUser := landing.EIHUser{
				ID:       edgeCredID,
				Email:    eihUserEmail(edgeCredID),
				Key:      edgeSecret,
				Source:   entrySrc,
				Role:     "relay",
				EgressIP: relayEgress,
			}
			landingUser := landing.EIHUser{
				ID:       hopCredID,
				Email:    eihUserEmail(hopCredID),
				Key:      hopSecret,
				Source:   relayEgress,
				Role:     "landing",
				UDP:      g.UDP,
				EgressIP: pr.EgressIP,
			}
			relayReadyForPending := !pr.PendingLegacyCutover || relay.MaxLandingRenderVersion >= landing.RenderVersion
			targetReadyForPending := !pr.PendingLegacyCutover || target.MaxLandingRenderVersion >= landing.RenderVersion
			if relayReadyForPending && !socketOccupiedBySingleUser(*relay.Desired.Landing, relayIngress) && !activeListenerCutoverBlocked(cutovers, member.NodeID, relayIngress) {
				addRelayTarget(member.NodeID, relayIngress, relayUser, landing.EIHRelayTarget{Address: pr.LandingAddress, Port: glivela.RelayPoolPort})
			}
			if targetReadyForPending && !socketOccupiedBySingleUser(*target.Desired.Landing, pr.LandingAddress) && !activeListenerCutoverBlocked(cutovers, pr.EgressID, pr.LandingAddress) {
				if err := addLandingUser(pr.EgressID, pr.LandingAddress, landingUser); err != nil {
					return false, err
				}
			}
			routeCandidates[grantID] = append(routeCandidates[grantID], plannedCandidate{
				relayNodeID:    member.NodeID,
				relayCertID:    member.CertificateID,
				entrySrc:       entrySrc,
				relayIngress:   relayIngress,
				edgeID:         edgeCredID,
				edgeKey:        relayKey.ServerKey + ":" + edgeSecret,
				landingAddress: pr.LandingAddress,
				landingKey:     targetKey.ServerKey + ":" + hopSecret,
				relayUser:      relayUser,
				landingUser:    landingUser,
			})
		}
	}

	// Build final sorted EIHListener slices per landing/relay node and update if changed.
	changed := false
	wantedEIH := map[string][]landing.EIHListener{}
	nodeAddrs := map[string][]string{}
	addAddr := func(nodeID, addr string) {
		if !slices.Contains(nodeAddrs[nodeID], addr) {
			nodeAddrs[nodeID] = append(nodeAddrs[nodeID], addr)
		}
	}
	for k := range relayUsers {
		addAddr(k.nodeID, k.address)
	}
	for k := range landingUsers {
		addAddr(k.nodeID, k.address)
	}
	for nodeID, addrs := range nodeAddrs {
		node, ok := byID[nodeID]
		if !ok || node.Desired.Landing == nil {
			continue
		}
		serverKey, hasKey := m.EIHNodeKeys[nodeID]
		if !hasKey || serverKey.CertificateID != node.CertificateID {
			continue
		}
		slices.Sort(addrs)
		for _, addr := range addrs {
			if socketOccupiedBySingleUser(*node.Desired.Landing, addr) {
				continue
			}
			k := eihKey{nodeID, addr}
			users := []landing.EIHUser{}
			for _, u := range landingUsers[k] {
				users = append(users, u)
			}
			for _, u := range relayUsers[k] {
				copyU := *u
				slices.SortFunc(copyU.RelayTargets, func(a, b landing.EIHRelayTarget) int {
					if c := strings.Compare(a.Address, b.Address); c != 0 {
						return c
					}
					return a.Port - b.Port
				})
				users = append(users, copyU)
			}
			if len(users) == 0 {
				continue
			}
			slices.SortFunc(users, func(a, b landing.EIHUser) int { return strings.Compare(a.ID, b.ID) })
			wantedEIH[nodeID] = append(wantedEIH[nodeID], landing.EIHListener{
				Address:   addr,
				Port:      glivela.RelayPoolPort,
				ServerKey: serverKey.ServerKey,
				Users:     users,
			})
		}
	}

	for cert, n := range nodes {
		if n.Desired.Landing == nil {
			continue
		}
		plan := *n.Desired.Landing
		nextListeners := wantedEIH[n.ID]
		if len(nextListeners) == 0 {
			nextListeners = nil
		}
		if reflect.DeepEqual(plan.EIHListeners, nextListeners) {
			continue
		}
		if plan.Revision == math.MaxUint64 {
			return false, errors.New("control: landing revision exhausted")
		}
		plan.EIHListeners = nextListeners
		plan.Revision++
		desired, err := NewDesired(plan)
		if err != nil {
			return false, err
		}
		n.Desired, n.Receipt, n.ReportedAt = desired, nil, time.Time{}
		n.Checks = nil
		nodes[cert] = n
		byID[n.ID] = n
		changed = true
	}

	// Attach finalized RelayTargets to plannedCandidate.relayUser so admission checks
	// verify the exact target set.
	for grantID, list := range routeCandidates {
		for i := range list {
			k := eihKey{list[i].relayNodeID, list[i].relayIngress}
			if u := relayUsers[k][list[i].edgeID]; u != nil {
				copyU := *u
				slices.SortFunc(copyU.RelayTargets, func(a, b landing.EIHRelayTarget) int {
					if c := strings.Compare(a.Address, b.Address); c != 0 {
						return c
					}
					return a.Port - b.Port
				})
				list[i].relayUser = copyU
			}
		}
		routeCandidates[grantID] = list
	}

	// Stage 2: Project RelayPools, deduplicated RelayEdges, ObservatoryConfig,
	// and EntryNetwork identities onto every enrolled entry node.
	for cert, node := range nodes {
		if node.Desired.Entry == nil || entryRetired(m, node.ID) {
			continue
		}
		desired := node.Desired.clone()
		plan := desired.Entry
		network := desired.EntryNetwork

		// Remember previously recorded identities so transient blips do not lose them.
		prevRelayIDs := map[string]EntryRelayNetworkPeer{}
		for _, rp := range network.RelayPeers {
			prevRelayIDs[rp.NodeID] = rp
		}
		prevLandingIDs := map[string]EntryPooledLanding{}
		for _, pl := range network.PooledLandings {
			prevLandingIDs[pl.EgressID] = pl
		}

		poolsByKey := map[string]glivela.EntryRelayPool{}
		edgesByID := map[string]glivela.EntryRelayEdge{}
		relayPeersByID := map[string]EntryRelayNetworkPeer{}
		pooledLandingsByID := map[string]EntryPooledLanding{}

		for _, grant := range plan.Grants {
			if grant.RelayPoolID == "" || m.DeletedRoutes[grant.ID] || !grant.Deployable() {
				continue
			}
			pr, hasPR := m.PooledRoutes[grant.ID]
			pool, hasPool := m.RelayPools[grant.RelayPoolID]
			if !hasPR || !hasPool {
				return false, errors.New("control: entry grant references missing relay pool route")
			}
			target, hasTarget := byID[grant.EgressID]
			if !hasTarget || target.Desired.Landing == nil || target.CertificateID != pr.LandingCertificateID {
				return false, errors.New("control: pooled route landing not enrolled")
			}
			expectedExit := pr.ExpectedExit
			if expectedExit == "" {
				expectedExit = target.Desired.Landing.EgressIP
			}
			var targetIdentity *landing.PeerIdentity
			if target.Receipt != nil && target.Receipt.ManagementIdentity != nil && target.Receipt.ManagementIdentity.Address == target.Desired.Landing.Address {
				id := *target.Receipt.ManagementIdentity
				targetIdentity = &id
			} else if prev, ok := prevLandingIDs[grant.EgressID]; ok && prev.CertificateID == target.CertificateID && prev.Identity != nil && prev.Identity.Address == target.Desired.Landing.Address {
				id := *prev.Identity
				targetIdentity = &id
			} else {
				for _, p := range network.Peers {
					if p.EgressID == grant.EgressID && p.Identity.Address == target.Desired.Landing.Address {
						id := p.Identity
						targetIdentity = &id
						break
					}
				}
			}
			pooledLandingsByID[grant.EgressID] = EntryPooledLanding{
				EgressID:      grant.EgressID,
				CertificateID: target.CertificateID,
				Identity:      targetIdentity,
				ExpectedExit:  expectedExit,
			}

			poolKey := grant.PoolKey()
			entryPool := glivela.EntryRelayPool{
				Key:       poolKey,
				GrantID:   grant.ID,
				AccountID: grant.AccountID,
				PoolID:    grant.RelayPoolID,
				EgressID:  grant.EgressID,
				UDP:       grant.UDP,
				Strategy:  pool.Strategy,
			}
			if !isSuspended(grant.EgressID) && !activeListenerCutoverBlocked(cutovers, pr.EgressID, pr.LandingAddress) && !socketOccupiedBySingleUser(*target.Desired.Landing, pr.LandingAddress) {
				for _, cand := range routeCandidates[grant.ID] {
					if activeListenerCutoverBlocked(cutovers, cand.relayNodeID, cand.relayIngress) {
						continue
					}
					relay := byID[cand.relayNodeID]
					if relay.Desired.Landing == nil || socketOccupiedBySingleUser(*relay.Desired.Landing, cand.relayIngress) {
						continue
					}
					edge := glivela.EntryRelayEdge{
						ID:          cand.edgeID,
						RelayNodeID: cand.relayNodeID,
						Source:      cand.entrySrc,
						Address:     cand.relayIngress,
						Port:        glivela.RelayPoolPort,
						Key:         cand.edgeKey,
					}
					entryCand := glivela.EntryPoolCandidate{
						RelayNodeID:    cand.relayNodeID,
						RelayEdgeID:    cand.edgeID,
						LandingAddress: cand.landingAddress,
						LandingPort:    glivela.RelayPoolPort,
						LandingKey:     cand.landingKey,
					}
					// Control-plane admission check: a candidate already active on this
					// entry stays active across transient heartbeat blips as long as its
					// desired credentials & certificates still match. Any new or rotated
					// candidate must first prove mTLS identity + applied receipt on BOTH
					// relay and downstream landing.
					alreadyActive := entryHasActiveCandidate(node, poolKey, entryCand, edge) &&
						hasEIHUser(*relay.Desired.Landing, cand.relayIngress, cand.relayUser) &&
						hasEIHUser(*target.Desired.Landing, cand.landingAddress, cand.landingUser)
					admitted := alreadyActive ||
						(nodeHasAppliedEIHUser(relay, cand.relayCertID, cand.relayIngress, cand.relayUser, now) &&
							nodeHasAppliedEIHUser(target, pr.LandingCertificateID, cand.landingAddress, cand.landingUser, now))
					if !admitted {
						continue
					}
					var relayIdentity *landing.PeerIdentity
					if relay.Receipt != nil && relay.Receipt.ManagementIdentity != nil && relay.Receipt.ManagementIdentity.Address == relay.Desired.Landing.Address {
						id := *relay.Receipt.ManagementIdentity
						relayIdentity = &id
					} else if prev, ok := prevRelayIDs[cand.relayNodeID]; ok && prev.CertificateID == relay.CertificateID && prev.Identity.Address == relay.Desired.Landing.Address {
						id := prev.Identity
						relayIdentity = &id
					}
					if relayIdentity == nil || targetIdentity == nil {
						continue
					}
					entryPool.Candidates = append(entryPool.Candidates, entryCand)
					edgesByID[edge.ID] = edge
					relayPeersByID[cand.relayNodeID] = EntryRelayNetworkPeer{
						NodeID:        cand.relayNodeID,
						CertificateID: relay.CertificateID,
						Identity:      *relayIdentity,
					}
				}
			}
			poolsByKey[poolKey] = entryPool
		}

		var nextPools []glivela.EntryRelayPool
		for _, ep := range poolsByKey {
			nextPools = append(nextPools, ep)
		}
		slices.SortFunc(nextPools, func(a, b glivela.EntryRelayPool) int { return strings.Compare(a.Key, b.Key) })
		var nextEdges []glivela.EntryRelayEdge
		for _, e := range edgesByID {
			nextEdges = append(nextEdges, e)
		}
		slices.SortFunc(nextEdges, func(a, b glivela.EntryRelayEdge) int { return strings.Compare(a.ID, b.ID) })
		var nextRelayPeers []EntryRelayNetworkPeer
		for _, rp := range relayPeersByID {
			nextRelayPeers = append(nextRelayPeers, rp)
		}
		slices.SortFunc(nextRelayPeers, func(a, b EntryRelayNetworkPeer) int { return strings.Compare(a.NodeID, b.NodeID) })
		var nextPooledLandings []EntryPooledLanding
		for _, pl := range pooledLandingsByID {
			nextPooledLandings = append(nextPooledLandings, pl)
		}
		slices.SortFunc(nextPooledLandings, func(a, b EntryPooledLanding) int { return strings.Compare(a.EgressID, b.EgressID) })

		var nextObs *glivela.ObservatoryConfig
		if len(nextPools) > 0 {
			if cfg, ok := m.EntryRelayConfigs[node.ID]; ok && cfg.Observatory != nil {
				obs := *cfg.Observatory
				nextObs = &obs
			}
		}

		// Clean up any retired single-relay three-hop legacy peers once their
		// explicit cutover has completed; never strip a PendingLegacyCutover peer.
		plan.Peers = slices.DeleteFunc(plan.Peers, func(p glivela.RoutePeer) bool {
			return p.Relay != nil && !isPendingLegacyThreeHop(m, p.Transport.ClientListenerID)
		})
		if len(plan.Peers) == 0 {
			plan.Peers = nil
		}
		network.Peers = slices.DeleteFunc(network.Peers, func(p EntryPeer) bool {
			return p.RelayIdentity != nil && !isPendingLegacyThreeHop(m, p.ClientChainID)
		})
		if len(network.Peers) == 0 {
			network.Peers = nil
		}
		if len(network.Peers) == 0 && len(nextRelayPeers) == 0 && len(nextPooledLandings) == 0 {
			network.Source = nil
		}

		plan.RelayPools = nextPools
		plan.RelayEdges = nextEdges
		plan.Observatory = nextObs
		network.RelayPeers = nextRelayPeers
		network.PooledLandings = nextPooledLandings

		if reflect.DeepEqual(plan, node.Desired.Entry) && reflect.DeepEqual(network, node.Desired.EntryNetwork) {
			continue
		}
		if plan.Revision == math.MaxUint64 {
			return false, errors.New("control: entry revision exhausted")
		}
		plan.Revision++
		version := desired.EntryRenderVersion
		if len(nextPools) > 0 || nextObs != nil {
			version = glivela.XrayRenderVersion
		}
		updated, err := newEntryDesiredVersion(*plan, *network, version)
		if err != nil {
			return false, err
		}
		node.Desired, node.Receipt, node.ReportedAt, node.EntryHealthBarrierAt = updated, nil, time.Time{}, time.Time{}
		nodes[cert] = node
		invalidateEntryChecks(nodes, node.ID)
		changed = true
	}
	return changed, nil
}

// CutoverLegacyPooledRoute switches a migrated v1 three-hop grant from its
// retained legacy single-relay runtime onto its v2 RelayPool ONLY after BOTH
// the relay and downstream landing have confirmed applied EIH 24000 receipts
// and the entry reports RelayPool render capability. Existing traffic stays on
// the legacy three-hop path whenever the relay is offline or port 24000 is
// still occupied.
func (s *Store) CutoverLegacyPooledRoute(ctx context.Context, grantID string) (AccountChangeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refused := errors.New("control: legacy three-hop cutover not ready")
	if ctx.Err() != nil {
		return AccountChangeResult{}, ctx.Err()
	}
	if !glivela.ValidIdentifier(grantID) || s.business == nil || s.business.faulted || s.business.material.Ownership == nil || s.business.material.ServerTransportVersion != glivela.CurrentServerTransportVersion {
		return AccountChangeResult{}, refused
	}
	now := time.Now().UTC()
	next := s.business.material
	pr, ok := next.PooledRoutes[grantID]
	if !ok || !pr.PendingLegacyCutover || next.DeletedRoutes[grantID] {
		return AccountChangeResult{}, refused
	}
	pool, hasPool := next.RelayPools[pr.RelayPoolID]
	if !hasPool {
		return AccountChangeResult{}, refused
	}
	byID := make(map[string]Node, len(s.nodes))
	for _, n := range s.nodes {
		byID[n.ID] = n
	}
	entry, hasEntry := byID[pr.EntryID]
	target, hasTarget := byID[pr.EgressID]
	if !hasEntry || entry.Desired.Entry == nil || !hasTarget || target.Desired.Landing == nil || target.CertificateID != pr.LandingCertificateID {
		return AccountChangeResult{}, refused
	}
	if !entrySupportsRelayPool(entry, now) || !landingSupportsEIH(target, now) || s.suspended(entry.ID, now) || s.suspended(target.ID, now) || socketOccupiedBySingleUser(*target.Desired.Landing, pr.LandingAddress) {
		return AccountChangeResult{}, refused
	}
	for _, c := range s.socketCutovers {
		if c.TargetNodeID == pr.EgressID && c.Address == pr.LandingAddress {
			return AccountChangeResult{}, errors.New("control: active socket cutover must finish before legacy three-hop cutover")
		}
		for _, consumer := range c.Consumers {
			if (pr.LegacyTransportID != "" && consumer.ServerTransportID == pr.LegacyTransportID) || consumer.GrantID == grantID {
				return AccountChangeResult{}, errors.New("control: active socket cutover must finish before legacy three-hop cutover")
			}
		}
	}

	// Verify at least one compatible pool member AND target landing already have
	// fresh applied EIH 24000 receipts so entry switches straight to a live candidate.
	_, serverGrants, err := effectiveBusinessCredentials(next, now)
	if err != nil {
		return AccountChangeResult{}, err
	}
	g, hasGrant := serverGrants[grantID]
	if !hasGrant || !g.Enabled || !g.Route.Enabled {
		return AccountChangeResult{}, refused
	}
	cfg := entryEffectiveRelayConfig(entry, next)
	readyCandidates := 0
	for _, member := range pool.Members {
		if member.IsDrained(now) || s.suspended(member.NodeID, now) || entryRetired(next, member.NodeID) {
			continue
		}
		relay, hasRelay := byID[member.NodeID]
		if !hasRelay || relay.Desired.Landing == nil || relay.CertificateID != member.CertificateID || !landingSupportsEIH(relay, now) {
			continue
		}
		entrySrc, relayIngress, _, relayEgress, _, compat := resolveRelayMemberHops(entry, cfg, member, pr)
		if !compat || socketOccupiedBySingleUser(*relay.Desired.Landing, relayIngress) {
			continue
		}
		edgeCredID := relayEdgeCredentialID(pr.EntryID, pr.AccountID, member.NodeID, entrySrc, relayIngress, relayEgress, g.UDP)
		hopCredID := landingHopCredentialID(pr.EntryID, pr.AccountID, member.NodeID, relayEgress, pr.EgressID, pr.LandingAddress, pr.EgressIP, g.UDP)
		edgeSecret := next.RelayPoolCredentials[edgeCredID]
		hopSecret := next.RelayPoolCredentials[hopCredID]
		if edgeSecret == "" || hopSecret == "" {
			continue
		}
		// Verify applied EIH users exist on BOTH relay (covering target) and target landing.
		relayReady := runtimeFresh(relay, now) && relay.Receipt != nil && relay.Receipt.ManagementIdentity != nil && relay.Receipt.ManagementIdentity.Address == relay.Desired.Landing.Address
		if relayReady {
			foundRelayUser := false
			for _, l := range relay.Desired.Landing.EIHListeners {
				if l.Address != relayIngress || l.Port != glivela.RelayPoolPort {
					continue
				}
				for _, u := range l.Users {
					if u.ID == edgeCredID && u.Role == "relay" && u.Key == edgeSecret && u.Source == entrySrc && u.EgressIP == relayEgress && slices.Contains(u.RelayTargets, landing.EIHRelayTarget{Address: pr.LandingAddress, Port: glivela.RelayPoolPort}) {
						foundRelayUser = true
					}
				}
			}
			relayReady = foundRelayUser
		}
		landingUser := landing.EIHUser{
			ID:       hopCredID,
			Email:    eihUserEmail(hopCredID),
			Key:      hopSecret,
			Source:   relayEgress,
			Role:     "landing",
			UDP:      g.UDP,
			EgressIP: pr.EgressIP,
		}
		if relayReady && nodeHasAppliedEIHUser(target, pr.LandingCertificateID, pr.LandingAddress, landingUser, now) {
			readyCandidates++
		}
	}
	if readyCandidates == 0 {
		return AccountChangeResult{}, errors.New("control: downstream EIH 24000 receipts pending; keeping legacy three-hop active")
	}

	// Atomically rebind the grant from legacy ClientChainID -> RelayPoolID.
	accounts := slices.Clone(next.Plan.Accounts)
	rebound := false
	for i := range accounts {
		if accounts[i].Account.ID != pr.AccountID {
			continue
		}
		accounts[i].Grants = slices.Clone(accounts[i].Grants)
		for j := range accounts[i].Grants {
			if accounts[i].Grants[j].ID != grantID {
				continue
			}
			if accounts[i].Grants[j].DesiredRev == math.MaxUint64 || accounts[i].Account.DesiredRevision == math.MaxUint64 {
				return AccountChangeResult{}, refused
			}
			accounts[i].Grants[j].ClientChainID = ""
			accounts[i].Grants[j].RelayPoolID = pr.RelayPoolID
			accounts[i].Grants[j].DesiredRev++
			accounts[i].Account.DesiredRevision++
			rebound = true
		}
	}
	if !rebound {
		return AccountChangeResult{}, refused
	}
	next.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		return AccountChangeResult{}, err
	}
	next.PooledRoutes = maps.Clone(next.PooledRoutes)
	pr.PendingLegacyCutover = false
	pr.RetiringLegacyTransport = pr.LegacyTransportID != ""
	next.PooledRoutes[grantID] = pr
	// Retain the legacy ServerTransport until the cut-over entry confirms an
	// applied receipt for its new RelayPool revision so relay/landing keep their
	// legacy listeners AND fresh EIH receipts intact during entry switchover.
	if err := ensurePooledRouteCredentials(s.nodes, &next); err != nil {
		return AccountChangeResult{}, err
	}
	gcUnreferencedRelayPoolCredentials(&next, s.nodes, s.socketCutovers)
	projected, changed, err := s.projectBusinessLocked(s.nodes, next, now)
	if err != nil {
		return AccountChangeResult{}, err
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return AccountChangeResult{}, err
	}
	if changed {
		if err := s.commit(projected); err != nil {
			return AccountChangeResult{}, err
		}
	}
	return s.accountChangeResult(pr.AccountID, now), nil
}

// retireCompletedLegacyThreeHops removes legacy single-relay ServerTransports
// and clears RetiringLegacyTransport flags only after explicit cutover AND
// fresh applied receipts on every cut-over entry.
func retireCompletedLegacyThreeHops(m *glivela.ImportMaterial, nodes map[string]Node, now time.Time) bool {
	if len(m.ServerTransports) == 0 && len(m.PooledRoutes) == 0 {
		return false
	}
	retiredIDs := map[string]bool{}
	for id, r := range m.ServerTransports {
		if (r.Peer.Relay != nil || r.RelayListener != nil) && !isRetainedLegacyThreeHop(nodes, *m, id, now) {
			retiredIDs[id] = true
		}
	}
	retiringCleared := false
	for grantID, pr := range m.PooledRoutes {
		if pr.RetiringLegacyTransport && !isRetainedLegacyThreeHop(nodes, *m, pr.LegacyTransportID, now) {
			if !retiringCleared {
				m.PooledRoutes = maps.Clone(m.PooledRoutes)
				retiringCleared = true
			}
			pr.RetiringLegacyTransport = false
			m.PooledRoutes[grantID] = pr
		}
	}
	if len(retiredIDs) == 0 && !retiringCleared {
		return false
	}
	if len(retiredIDs) > 0 {
		m.ServerTransports = maps.Clone(m.ServerTransports)
		for id := range retiredIDs {
			delete(m.ServerTransports, id)
		}
		if len(m.ServerTransports) == 0 {
			m.ServerTransports = nil
		}
	}
	return true
}

// ChangeRelayPool creates, updates (including member reorder, strategy edits,
// member-level drain/undrain, and offline member removal), or deletes a named
// RelayPool. Removing an offline (!runtimeFresh) relay immediately submits
// updated entry & downstream landing configurations and reports revocation
// progress based on affected entry & landing applied receipts.
func (s *Store) ChangeRelayPool(ctx context.Context, change RelayPoolChange) (RelayPoolChangeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refused := errors.New("control: relay pool change refused")
	if ctx.Err() != nil {
		return RelayPoolChangeResult{}, ctx.Err()
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil || s.business.material.ServerTransportVersion != glivela.CurrentServerTransportVersion {
		return RelayPoolChangeResult{}, refused
	}
	next := s.business.material
	old, exists := next.RelayPools[change.Pool.ID]
	if change.Delete {
		if !exists || change.ExpectedRevision != old.Revision {
			return RelayPoolChangeResult{}, refused
		}
		for _, a := range next.Plan.Accounts {
			for _, g := range a.Grants {
				if !next.DeletedRoutes[g.ID] && g.RelayPoolID == old.ID {
					return RelayPoolChangeResult{}, errors.New("control: relay pool is still referenced by routes")
				}
			}
		}
		for _, pr := range next.PooledRoutes {
			if !next.DeletedRoutes[pr.GrantID] && pr.RelayPoolID == old.ID {
				return RelayPoolChangeResult{}, errors.New("control: relay pool is still referenced by routes")
			}
		}
		next.RelayPools = maps.Clone(next.RelayPools)
		delete(next.RelayPools, old.ID)
		if len(next.RelayPools) == 0 {
			next.RelayPools = nil
		}
		gcUnreferencedRelayPoolCredentials(&next, s.nodes, s.socketCutovers)
		if err := s.saveOwnedBusinessLocked(next); err != nil {
			return RelayPoolChangeResult{}, err
		}
		return RelayPoolChangeResult{PoolID: old.ID, Revision: old.Revision, Deleted: true, Revocation: RelayPoolRevocationStatus{PendingEntries: []string{}, PendingLandings: []string{}, Complete: true}}, nil
	}

	pool := change.Pool
	pool.Members = slices.Clone(pool.Members)
	if !exists {
		if change.ExpectedRevision != 0 {
			return RelayPoolChangeResult{}, refused
		}
		pool.Revision = 1
	} else {
		if change.ExpectedRevision != old.Revision || old.Revision == math.MaxUint64 {
			return RelayPoolChangeResult{}, refused
		}
		pool.Revision = old.Revision + 1
	}
	if pool.Validate() != nil {
		return RelayPoolChangeResult{}, refused
	}

	byID := make(map[string]Node, len(s.nodes))
	for _, n := range s.nodes {
		byID[n.ID] = n
	}
	// Verify every member in the updated pool is an enrolled non-retired landing
	// node with matching certificate. Offline members being REMOVED are absent
	// from pool.Members and are explicitly permitted to be removed while offline.
	for _, member := range pool.Members {
		node, ok := byID[member.NodeID]
		if !ok || node.Desired.Landing == nil || node.CertificateID != member.CertificateID || entryRetired(next, member.NodeID) {
			return RelayPoolChangeResult{}, errors.New("control: relay pool member is not an enrolled landing node")
		}
	}

	next.RelayPools = maps.Clone(next.RelayPools)
	if next.RelayPools == nil {
		next.RelayPools = map[string]glivela.RelayPool{}
	}
	next.RelayPools[pool.ID] = pool

	if err := ensurePooledRouteCredentials(s.nodes, &next); err != nil {
		return RelayPoolChangeResult{}, err
	}
	gcUnreferencedRelayPoolCredentials(&next, s.nodes, s.socketCutovers)

	now := time.Now().UTC()
	projected, changed, err := s.projectBusinessLocked(s.nodes, next, now)
	if err != nil {
		return RelayPoolChangeResult{}, err
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return RelayPoolChangeResult{}, err
	}
	if changed {
		if err := s.commit(projected); err != nil {
			return RelayPoolChangeResult{}, err
		}
	}
	revocation := s.poolRevocationStatusLocked(pool.ID, now)
	return RelayPoolChangeResult{PoolID: pool.ID, Revision: pool.Revision, Revocation: revocation}, nil
}

// poolRevocationStatusLocked reports whether all entries and downstream landings
// affected by poolID have reported fresh applied receipts matching their current
// desired revisions. Offline removed relays do not block revocation completion.
func (s *Store) poolRevocationStatusLocked(poolID string, now time.Time) RelayPoolRevocationStatus {
	status := RelayPoolRevocationStatus{PendingEntries: []string{}, PendingLandings: []string{}, Complete: true}
	if s.business == nil {
		return status
	}
	entries := map[string]bool{}
	landings := map[string]bool{}
	for _, pr := range s.business.material.PooledRoutes {
		if pr.RelayPoolID != poolID || s.business.material.DeletedRoutes[pr.GrantID] {
			continue
		}
		entries[pr.EntryID] = true
		landings[pr.EgressID] = true
	}
	byID := map[string]Node{}
	for _, n := range s.nodes {
		byID[n.ID] = n
	}
	for id := range entries {
		if n, ok := byID[id]; !ok || !runtimeFresh(n, now) {
			status.PendingEntries = append(status.PendingEntries, id)
		}
	}
	for id := range landings {
		if n, ok := byID[id]; !ok || !runtimeFresh(n, now) {
			status.PendingLandings = append(status.PendingLandings, id)
		}
	}
	slices.Sort(status.PendingEntries)
	slices.Sort(status.PendingLandings)
	status.Complete = len(status.PendingEntries) == 0 && len(status.PendingLandings) == 0
	return status
}

// ChangeEntryRelayConfig updates an entry's process-level burstObservatory
// pingConfig and/or explicit public source addresses.
func (s *Store) ChangeEntryRelayConfig(ctx context.Context, change EntryRelayConfigChange) (EntryRelayConfigView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refused := errors.New("control: entry observatory config change refused")
	if ctx.Err() != nil {
		return EntryRelayConfigView{}, ctx.Err()
	}
	if !glivela.ValidIdentifier(change.EntryID) || change.ExpectedRevision == 0 || change.Config.Validate() != nil ||
		s.business == nil || s.business.faulted || s.business.material.Ownership == nil ||
		s.business.material.ServerTransportVersion != glivela.CurrentServerTransportVersion || s.entryRetiredLocked(change.EntryID) {
		return EntryRelayConfigView{}, refused
	}
	var entryCert string
	var entry Node
	for cert, n := range s.nodes {
		if n.ID == change.EntryID && n.Desired.Entry != nil {
			entryCert, entry = cert, n
			break
		}
	}
	if entryCert == "" || entry.Desired.Revision != change.ExpectedRevision {
		return EntryRelayConfigView{}, refused
	}
	next := s.business.material
	oldCfg, hadCfg := next.EntryRelayConfigs[change.EntryID]
	currentCfgRev := oldCfg.Revision
	if change.ExpectedConfigRevision != nil && *change.ExpectedConfigRevision != currentCfgRev {
		return EntryRelayConfigView{}, refused
	}
	next.EntryRelayConfigs = maps.Clone(next.EntryRelayConfigs)
	if next.EntryRelayConfigs == nil {
		next.EntryRelayConfigs = map[string]glivela.EntryRelayConfig{}
	}
	cfg := change.Config
	if cfg.Observatory != nil {
		obs := *cfg.Observatory
		cfg.Observatory = &obs
	}
	emptyConfig := cfg.SourceIPv4 == "" && cfg.SourceIPv6 == "" && cfg.Observatory == nil
	if emptyConfig && !hadCfg {
		cfg.Revision = 0
		delete(next.EntryRelayConfigs, change.EntryID)
		if len(next.EntryRelayConfigs) == 0 {
			next.EntryRelayConfigs = nil
		}
	} else {
		if currentCfgRev == math.MaxUint64 {
			return EntryRelayConfigView{}, refused
		}
		cfg.Revision = currentCfgRev + 1
		next.EntryRelayConfigs[change.EntryID] = cfg
	}
	if err := ensurePooledRouteCredentials(s.nodes, &next); err != nil {
		return EntryRelayConfigView{}, err
	}
	gcUnreferencedRelayPoolCredentials(&next, s.nodes, s.socketCutovers)
	now := time.Now().UTC()
	projected, changed, err := s.projectBusinessLocked(s.nodes, next, now)
	if err != nil {
		return EntryRelayConfigView{}, err
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return EntryRelayConfigView{}, err
	}
	if changed {
		if err := s.commit(projected); err != nil {
			return EntryRelayConfigView{}, err
		}
	}
	return EntryRelayConfigView{
		EntryID:        change.EntryID,
		Revision:       s.nodes[entryCert].Desired.Revision,
		ConfigRevision: cfg.Revision,
		Config:         cfg,
	}, nil
}

func (s *Store) relayPoolViewsLocked(now time.Time) []RelayPoolView {
	views := []RelayPoolView{}
	if s.business == nil {
		return views
	}
	m := s.business.material
	byID := make(map[string]Node, len(s.nodes))
	for _, n := range s.nodes {
		byID[n.ID] = n
	}
	for _, pool := range m.RelayPools {
		v := RelayPoolView{
			ID:         pool.ID,
			Name:       pool.Name,
			Revision:   pool.Revision,
			Strategy:   pool.Strategy,
			Members:    make([]RelayPoolMemberView, 0, len(pool.Members)),
			RouteIDs:   []string{},
			Revocation: s.poolRevocationStatusLocked(pool.ID, now),
		}
		for _, member := range pool.Members {
			node, ok := byID[member.NodeID]
			v.Members = append(v.Members, RelayPoolMemberView{
				NodeID:        member.NodeID,
				CertificateID: member.CertificateID,
				IngressIPv4:   member.IngressIPv4,
				IngressIPv6:   member.IngressIPv6,
				EgressIPv4:    member.EgressIPv4,
				EgressIPv6:    member.EgressIPv6,
				Drained:       member.IsDrained(now),
				DrainReason:   member.DrainReason,
				DrainResumeAt: member.DrainResumeAt,
				NodeSuspended: s.suspended(member.NodeID, now),
				RuntimeReady:  ok && runtimeFresh(node, now),
			})
		}
		seenRoutes := map[string]bool{}
		for _, a := range m.Plan.Accounts {
			for _, g := range a.Grants {
				if m.DeletedRoutes[g.ID] || seenRoutes[g.ID] {
					continue
				}
				if g.RelayPoolID == pool.ID || m.PooledRoutes[g.ID].RelayPoolID == pool.ID {
					seenRoutes[g.ID] = true
					v.RouteIDs = append(v.RouteIDs, g.ID)
				}
			}
		}
		slices.Sort(v.RouteIDs)
		views = append(views, v)
	}
	slices.SortFunc(views, func(a, b RelayPoolView) int { return strings.Compare(a.ID, b.ID) })
	return views
}

// runtimeRelayMetadata returns strictly non-secret relay capability, public
// address hints, and single-user port-24000 occupancy for BusinessRuntime.
func runtimeRelayMetadata(node Node, m *glivela.ImportMaterial) (capable bool, publicIPv4, publicIPv6, egressIP string, occupied24000 []string) {
	if node.Desired.Entry != nil {
		capable = entryKnownRelayPoolCapable(node)
		var cfg glivela.EntryRelayConfig
		if m != nil {
			cfg = entryEffectiveRelayConfig(node, *m)
		} else if len(node.Desired.Entry.RealityEndpoints) > 0 {
			ep := node.Desired.Entry.RealityEndpoints[0]
			if glivela.PublicTransportIPv6(ep.ListenAddress) {
				cfg.SourceIPv6 = ep.ListenAddress
			}
			if glivela.PublicTransportIPv4(ep.IPv4ListenAddress) {
				cfg.SourceIPv4 = ep.IPv4ListenAddress
			}
		}
		return capable, cfg.SourceIPv4, cfg.SourceIPv6, "", nil
	}
	if node.Desired.Landing == nil {
		return false, "", "", "", nil
	}
	plan := *node.Desired.Landing
	capable = node.MaxLandingRenderVersion >= landing.RenderVersion
	egressIP = plan.EgressIP
	recordAddr := func(addr string) {
		if publicIPv4 == "" && glivela.PublicTransportIPv4(addr) {
			publicIPv4 = addr
		}
		if publicIPv6 == "" && glivela.PublicTransportIPv6(addr) {
			publicIPv6 = addr
		}
	}
	recordAddr(plan.Transport.PublicAddress)
	recordAddr(plan.IPv6OnlyAddress)
	for _, l := range plan.EIHListeners {
		recordAddr(l.Address)
	}
	seenOccupied := map[string]bool{}
	checkOccupied := func(addr string) {
		if addr == "" || seenOccupied[addr] || !(glivela.PublicTransportIPv4(addr) || glivela.PublicTransportIPv6(addr)) {
			return
		}
		if socketOccupiedBySingleUser(plan, addr) {
			seenOccupied[addr] = true
			occupied24000 = append(occupied24000, addr)
		}
	}
	checkOccupied(plan.Transport.Endpoint(plan.Address))
	for _, c := range plan.ActiveClientListeners() {
		cAddr := plan.Transport.PublicAddress
		if c.Transport == "ipv6-ss2022" || c.Interface != "" {
			cAddr = c.Address
		}
		recordAddr(cAddr)
		checkOccupied(cAddr)
	}
	slices.Sort(occupied24000)
	return capable, publicIPv4, publicIPv6, egressIP, occupied24000
}
