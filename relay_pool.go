package glivela

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	CurrentServerTransportVersion uint8 = 2

	RelayPoolPort                 = 24000
	DefaultObservatoryDestination = "https://www.gstatic.com/generate_204"
	DefaultObservatoryIntervalSec = 10
	MinObservatoryIntervalSec     = 10
	MaxObservatoryIntervalSec     = 300
	DefaultObservatorySampling    = 3
	DefaultObservatoryTimeoutSec  = 5
	DefaultRelayPoolMaxRTTMS      = 500
	DefaultRelayPoolTolerance     = 0.05
)

// ValidSS2022Key16 reports whether value is a canonical 16-byte standard base64
// key for 2022-blake3-aes-128-gcm.
func ValidSS2022Key16(value string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 16 && base64.StdEncoding.EncodeToString(raw) == value
}

// ValidEIHKey reports whether value is a canonical SS2022 EIH multi-user
// key formatted as "<16B-server-iPSK>:<16B-uPSK>".
func ValidEIHKey(value string) bool {
	serverKey, userKey, ok := strings.Cut(value, ":")
	return ok && !strings.Contains(userKey, ":") && ValidSS2022Key16(serverKey) && ValidSS2022Key16(userKey)
}

// ObservatoryConfig owns an entry Xray process's single burstObservatory.pingConfig.
type ObservatoryConfig struct {
	Destination string `json:"destination"`
	IntervalSec int    `json:"intervalSec"`
	Sampling    int    `json:"sampling"`
	TimeoutSec  int    `json:"timeoutSec"`
}

func DefaultObservatoryConfig() ObservatoryConfig {
	return ObservatoryConfig{
		Destination: DefaultObservatoryDestination,
		IntervalSec: DefaultObservatoryIntervalSec,
		Sampling:    DefaultObservatorySampling,
		TimeoutSec:  DefaultObservatoryTimeoutSec,
	}
}

func (c ObservatoryConfig) Validate() error {
	if c.Destination == "" || len(c.Destination) > 512 || strings.TrimSpace(c.Destination) != c.Destination || strings.ContainsAny(c.Destination, "\x00\r\n") {
		return errors.New("glivela: invalid observatory destination")
	}
	u, err := url.Parse(c.Destination)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("glivela: invalid observatory destination URL")
	}
	if c.IntervalSec < MinObservatoryIntervalSec || c.IntervalSec > MaxObservatoryIntervalSec || c.Sampling < 1 || c.Sampling > 10 || c.TimeoutSec < 1 || c.TimeoutSec > 30 || c.TimeoutSec > c.IntervalSec {
		return errors.New("glivela: invalid observatory pingConfig parameters")
	}
	return nil
}

// EntryRelayConfig stores per-entry public source addresses and the entry's
// process-level burstObservatory configuration. Revision is controller-managed
// optimistic concurrency state so concurrent edits conflict even before any
// pooled route binds this entry (without bumping entry Desired.Revision).
type EntryRelayConfig struct {
	Revision    uint64             `json:"revision,string,omitempty"`
	SourceIPv4  string             `json:"sourceIpv4,omitempty"`
	SourceIPv6  string             `json:"sourceIpv6,omitempty"`
	Observatory *ObservatoryConfig `json:"observatory,omitempty"`
}

func (c EntryRelayConfig) Validate() error {
	if c.SourceIPv4 != "" && !PublicTransportIPv4(c.SourceIPv4) {
		return errors.New("glivela: invalid entry relay IPv4 source")
	}
	if c.SourceIPv6 != "" && !PublicTransportIPv6(c.SourceIPv6) {
		return errors.New("glivela: invalid entry relay IPv6 source")
	}
	if c.Observatory != nil {
		if err := c.Observatory.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// RelayPoolStrategy configures pool-level leastLoad selection on an entry.
// Expected must be explicitly >= 1 so Xray leastLoad distributes across candidates.
type RelayPoolStrategy struct {
	Expected  int     `json:"expected"`
	MaxRTTMS  int     `json:"maxRttMs"`
	Tolerance float64 `json:"tolerance,omitempty"`
}

func DefaultRelayPoolStrategy(expected int) RelayPoolStrategy {
	if expected < 1 {
		expected = 1
	}
	return RelayPoolStrategy{
		Expected:  expected,
		MaxRTTMS:  DefaultRelayPoolMaxRTTMS,
		Tolerance: DefaultRelayPoolTolerance,
	}
}

func (s RelayPoolStrategy) Validate() error {
	if s.Expected < 1 || s.Expected > 64 || s.MaxRTTMS < 50 || s.MaxRTTMS > 30000 || math.IsNaN(s.Tolerance) || math.IsInf(s.Tolerance, 0) || s.Tolerance < 0 || s.Tolerance > 1 {
		return errors.New("glivela: invalid relay pool strategy")
	}
	return nil
}

// RelayPoolMember is one ordered relay candidate inside a RelayPool. Member
// drain is modeled independently of node-level availability so draining a
// dual-role host from a relay pool does not withdraw its fixed-landing route.
type RelayPoolMember struct {
	NodeID        string    `json:"nodeId"`
	CertificateID string    `json:"certificateId"`
	IngressIPv4   string    `json:"ingressIpv4,omitempty"`
	IngressIPv6   string    `json:"ingressIpv6,omitempty"`
	EgressIPv4    string    `json:"egressIpv4,omitempty"`
	EgressIPv6    string    `json:"egressIpv6,omitempty"`
	Drained       bool      `json:"drained,omitempty"`
	DrainReason   string    `json:"drainReason,omitempty"`
	DrainResumeAt time.Time `json:"drainResumeAt,omitempty"`
}

func (m RelayPoolMember) Validate() error {
	if !ValidIdentifier(m.NodeID) || !ValidIdentity(m.CertificateID) {
		return errors.New("glivela: invalid relay pool member identity")
	}
	if m.IngressIPv4 == "" && m.IngressIPv6 == "" {
		return errors.New("glivela: relay pool member requires an ingress address")
	}
	if m.EgressIPv4 == "" && m.EgressIPv6 == "" {
		return errors.New("glivela: relay pool member requires an egress source")
	}
	if m.IngressIPv4 != "" && !PublicTransportIPv4(m.IngressIPv4) {
		return errors.New("glivela: invalid relay member IPv4 ingress")
	}
	if m.IngressIPv6 != "" && !PublicTransportIPv6(m.IngressIPv6) {
		return errors.New("glivela: invalid relay member IPv6 ingress")
	}
	if m.EgressIPv4 != "" {
		ip, err := netip.ParseAddr(m.EgressIPv4)
		if err != nil || !ip.Is4() || ip.String() != m.EgressIPv4 || !(PublicTransportIPv4(m.EgressIPv4) || ip.IsPrivate()) {
			return errors.New("glivela: invalid relay member IPv4 egress")
		}
	}
	if m.EgressIPv6 != "" && !PublicTransportIPv6(m.EgressIPv6) {
		return errors.New("glivela: invalid relay member IPv6 egress")
	}
	if !m.Drained && (m.DrainReason != "" || !m.DrainResumeAt.IsZero()) {
		return errors.New("glivela: drain metadata requires drained state")
	}
	if len([]rune(m.DrainReason)) > 128 || strings.TrimSpace(m.DrainReason) != m.DrainReason || strings.ContainsAny(m.DrainReason, "\x00\r\n") {
		return errors.New("glivela: invalid relay drain reason")
	}
	return nil
}

// IsDrained reports whether this member is currently drained at now.
func (m RelayPoolMember) IsDrained(now time.Time) bool {
	if !m.Drained {
		return false
	}
	return m.DrainResumeAt.IsZero() || now.Before(m.DrainResumeAt)
}

// RelayPool is a first-class named, ordered dynamic relay pool for three-hop
// forwarding toward fixed landings.
type RelayPool struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Revision uint64            `json:"revision,string"`
	Strategy RelayPoolStrategy `json:"strategy"`
	Members  []RelayPoolMember `json:"members"`
}

func (p RelayPool) Validate() error {
	if !ValidIdentifier(p.ID) || !validDisplayName(p.Name) || p.Revision == 0 || p.Strategy.Validate() != nil || len(p.Members) > 64 {
		return errors.New("glivela: invalid relay pool")
	}
	seenNodes, seenCerts := map[string]bool{}, map[string]bool{}
	for _, member := range p.Members {
		if member.Validate() != nil || seenNodes[member.NodeID] || seenCerts[member.CertificateID] {
			return errors.New("glivela: invalid or duplicate relay pool member")
		}
		seenNodes[member.NodeID], seenCerts[member.CertificateID] = true, true
	}
	return nil
}

// EIHNodeKey stores one enrolled node's canonical 16-byte SS2022 server-iPSK
// for its single-port 24000 multi-user EIH listener(s).
type EIHNodeKey struct {
	NodeID        string `json:"nodeId"`
	CertificateID string `json:"certificateId"`
	ServerKey     string `json:"serverKey"`
}

func (k EIHNodeKey) Validate() error {
	if !ValidIdentifier(k.NodeID) || !ValidIdentity(k.CertificateID) || !ValidSS2022Key16(k.ServerKey) {
		return errors.New("glivela: invalid EIH node server key")
	}
	return nil
}

// PooledRoute binds one logical three-hop RouteGrant to a RelayPool and fixed
// landing without duplicating per-relay transport records.
type PooledRoute struct {
	GrantID              string `json:"grantId"`
	AccountID            string `json:"accountId"`
	EntryID              string `json:"entryId"`
	EgressID             string `json:"egressId"`
	RelayPoolID          string `json:"relayPoolId"`
	LandingCertificateID string `json:"landingCertificateId"`
	LandingAddress       string `json:"landingAddress"`
	ExpectedExit         string `json:"expectedExit"`
	EgressIP             string `json:"egressIp,omitempty"`
	IngressFamily        string `json:"ingressFamily,omitempty"` // "", "ipv4", or "ipv6"
	Name                 string `json:"name,omitempty"`
	LegacyTransportID    string `json:"legacyTransportId,omitempty"`
	// PendingLegacyCutover retains the migrated v1 three-hop runtime until
	// downstream EIH 24000 receipts confirm readiness and explicit cutover runs.
	// RetiringLegacyTransport retains the legacy ServerTransport after explicit
	// cutover until the cut-over entry confirms its applied RelayPool receipt.
	PendingLegacyCutover    bool `json:"pendingLegacyCutover,omitempty"`
	RetiringLegacyTransport bool `json:"retiringLegacyTransport,omitempty"`
}

func (r PooledRoute) Validate() error {
	if !ValidIdentifier(r.GrantID) || !ValidIdentifier(r.AccountID) || !ValidIdentifier(r.EntryID) || !ValidIdentifier(r.EgressID) || !ValidIdentifier(r.RelayPoolID) || !ValidIdentity(r.LandingCertificateID) || r.EntryID == r.EgressID {
		return errors.New("glivela: invalid pooled route identity")
	}
	if !PublicTransportIPv4(r.LandingAddress) && !PublicTransportIPv6(r.LandingAddress) {
		return errors.New("glivela: pooled route requires exact public landing address")
	}
	if r.IngressFamily != "" && r.IngressFamily != "ipv4" && r.IngressFamily != "ipv6" {
		return errors.New("glivela: invalid pooled route ingress family")
	}
	if r.ExpectedExit != "" {
		ip, err := netip.ParseAddr(r.ExpectedExit)
		if err != nil || ip.String() != r.ExpectedExit {
			return errors.New("glivela: invalid pooled route expected exit")
		}
	}
	if r.EgressIP != "" {
		ip, err := netip.ParseAddr(r.EgressIP)
		if err != nil || ip.String() != r.EgressIP || !(PublicTransportIPv4(r.EgressIP) || PublicTransportIPv6(r.EgressIP) || ip.Is4() && ip.IsPrivate()) {
			return errors.New("glivela: invalid pooled route egress source")
		}
	}
	if r.Name != "" && !validDisplayName(r.Name) {
		return errors.New("glivela: invalid pooled route name")
	}
	if r.LegacyTransportID != "" && !ValidIdentifier(r.LegacyTransportID) {
		return errors.New("glivela: invalid legacy transport reference")
	}
	if (r.PendingLegacyCutover || r.RetiringLegacyTransport) && r.LegacyTransportID == "" {
		return errors.New("glivela: legacy cutover transition requires legacy transport reference")
	}
	if r.PendingLegacyCutover && r.RetiringLegacyTransport {
		return errors.New("glivela: pooled route cannot be both pending and retiring legacy cutover")
	}
	return nil
}

// TwoHopEIHBinding tracks a two-hop peer whose shared port 24000 listener was
// transitioned from legacy single-user SS2022 to multi-user EIH 24000 via the
// controlled socket cutover window.
type TwoHopEIHBinding struct {
	ID              string `json:"id"`
	EntryID         string `json:"entryId"`
	EgressID        string `json:"egressId"`
	LandingAddress  string `json:"landingAddress"`
	Source          string `json:"source"`
	CredentialID    string `json:"credentialId"`
	EgressIP        string `json:"egressIp,omitempty"`
	UDP             bool   `json:"udp,omitempty"`
	ClientChainID   string `json:"clientChainId,omitempty"`
	ServerTransport string `json:"serverTransportId,omitempty"`
}

func (b TwoHopEIHBinding) Validate() error {
	if !ValidIdentifier(b.ID) || !ValidIdentifier(b.EntryID) || !ValidIdentifier(b.EgressID) || b.EntryID == b.EgressID || !ValidIdentifier(b.CredentialID) {
		return errors.New("glivela: invalid two-hop EIH binding")
	}
	isV4 := PublicTransportIPv4(b.LandingAddress)
	isV6 := PublicTransportIPv6(b.LandingAddress)
	if (!isV4 && !isV6) || b.Source == b.LandingAddress || isV4 && !PublicTransportIPv4(b.Source) || isV6 && !PublicTransportIPv6(b.Source) {
		return errors.New("glivela: invalid two-hop EIH addresses")
	}
	if b.EgressIP != "" {
		ip, err := netip.ParseAddr(b.EgressIP)
		if err != nil || ip.String() != b.EgressIP || !(PublicTransportIPv4(b.EgressIP) || PublicTransportIPv6(b.EgressIP) || ip.Is4() && ip.IsPrivate()) {
			return errors.New("glivela: invalid two-hop EIH egress source")
		}
	}
	if b.ClientChainID != "" && !ValidIdentifier(b.ClientChainID) || b.ServerTransport != "" && !ValidIdentifier(b.ServerTransport) {
		return errors.New("glivela: invalid two-hop EIH transport reference")
	}
	return nil
}

// EntryRelayEdge is one deduplicated physical (entry -> relay:24000) SS2022 EIH
// outbound on an entry XrayPlan. Routes with identical authorization reuse it.
// Source binds sendThrough so multi-IP entries always dial from the exact
// source address authorized in relay EIH and firewall policies.
type EntryRelayEdge struct {
	ID          string `json:"id"`
	RelayNodeID string `json:"relayNodeId"`
	Source      string `json:"source"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Key         string `json:"key"`
}

func (e EntryRelayEdge) Validate() error {
	isV4 := PublicTransportIPv4(e.Address)
	isV6 := PublicTransportIPv6(e.Address)
	if !ValidIdentifier(e.ID) || !ValidIdentifier(e.RelayNodeID) || e.Port != RelayPoolPort || (!isV4 && !isV6) || e.Source == e.Address || !ValidEIHKey(e.Key) {
		return errors.New("glivela: invalid entry relay edge")
	}
	if isV4 && !PublicTransportIPv4(e.Source) || isV6 && !PublicTransportIPv6(e.Source) {
		return errors.New("glivela: entry relay edge source family mismatch")
	}
	return nil
}

// EntryPoolCandidate is one ordered, authorized full path (entry -> relay -> landing)
// inside an EntryRelayPool.
type EntryPoolCandidate struct {
	RelayNodeID    string `json:"relayNodeId"`
	RelayEdgeID    string `json:"relayEdgeId"`
	LandingAddress string `json:"landingAddress"`
	LandingPort    int    `json:"landingPort"`
	LandingKey     string `json:"landingKey"`
}

func (c EntryPoolCandidate) Validate() error {
	if !ValidIdentifier(c.RelayNodeID) || !ValidIdentifier(c.RelayEdgeID) || c.LandingPort != RelayPoolPort || !(PublicTransportIPv4(c.LandingAddress) || PublicTransportIPv6(c.LandingAddress)) || !ValidEIHKey(c.LandingKey) {
		return errors.New("glivela: invalid entry pool candidate")
	}
	return nil
}

// EntryRelayPool binds one logical pooled RouteGrant on an entry to its
// ordered active full-path candidates. Empty Candidates routes to "blocked".
// Keying per GrantID prevents routes with distinct LandingAddress or EgressIP
// from colliding while still reusing deduplicated physical EntryRelayEdges.
type EntryRelayPool struct {
	Key        string               `json:"key"`
	GrantID    string               `json:"grantId"`
	AccountID  string               `json:"accountId"`
	PoolID     string               `json:"poolId"`
	EgressID   string               `json:"egressId"`
	UDP        bool                 `json:"udp,omitempty"`
	Strategy   RelayPoolStrategy    `json:"strategy"`
	Candidates []EntryPoolCandidate `json:"candidates"`
}

func PooledRouteKey(grantID string) string {
	sum := sha256.Sum256([]byte("grant-pool\x00" + grantID))
	return "pool-" + hex.EncodeToString(sum[:16])
}

func RelayEdgeOutboundTag(edgeID string) string {
	return "relay-edge-" + edgeID
}

func PoolBalancerTag(poolKey string) string {
	return "bal-" + Identity(poolKey)[:16]
}

func PoolCandidatePrefix(poolKey string) string {
	return "pool-" + Identity(poolKey)[:16] + "-"
}

func PoolCandidateTag(poolKey string, index int) string {
	return fmt.Sprintf("%sc%02d", PoolCandidatePrefix(poolKey), index)
}

func (p EntryRelayPool) Validate() error {
	if !ValidIdentifier(p.Key) || !ValidIdentifier(p.GrantID) || !ValidIdentifier(p.AccountID) || !ValidIdentifier(p.PoolID) || !ValidIdentifier(p.EgressID) || p.Strategy.Validate() != nil || len(p.Candidates) > 64 {
		return errors.New("glivela: invalid entry relay pool")
	}
	if p.Key != PooledRouteKey(p.GrantID) {
		return errors.New("glivela: entry relay pool key mismatch")
	}
	seenRelays := map[string]bool{}
	for _, c := range p.Candidates {
		if c.Validate() != nil || c.RelayNodeID == p.EgressID || seenRelays[c.RelayNodeID] {
			return errors.New("glivela: invalid entry relay pool candidate")
		}
		seenRelays[c.RelayNodeID] = true
	}
	return nil
}
