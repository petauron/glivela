package glivela

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// RetiredLanding retains only a revocation fence, never a reusable credential.
// HostID also fences the original host when an entry has a distinct runtime ID.
type RetiredLanding struct {
	HostID        string `json:"hostId,omitempty"`
	CertificateID string `json:"certificateId"`
	Revision      uint64 `json:"revision,string"`
}

// ImportMaterial is one atomic, sensitive handover checkpoint. RetainedSource
// is migration history, never a second live configuration source. An explicit
// offline retirement operation may redact expired-host history while retaining
// its source identity header. Never send this material in a receipt or logs.
type ImportMaterial struct {
	// Only authenticated loads populate this cache; its fingerprint is checked
	// against current bytes on use, so in-place archive edits cannot reuse it.
	sourceCache *importSourceCache

	ServerTransportVersion uint8                       `json:"serverTransportVersion,omitempty"`
	ServerTransports       map[string]ServerTransport  `json:"serverTransports,omitempty"`
	EntryRelayConfigs      map[string]EntryRelayConfig `json:"entryRelayConfigs,omitempty"`
	RelayPools             map[string]RelayPool        `json:"relayPools,omitempty"`
	PooledRoutes           map[string]PooledRoute      `json:"pooledRoutes,omitempty"`
	TwoHopEIHBindings      map[string]TwoHopEIHBinding `json:"twoHopEihBindings,omitempty"`
	EIHNodeKeys            map[string]EIHNodeKey       `json:"eihNodeKeys,omitempty"`
	// RelayPoolCredentials maps deterministic authorization scope IDs to
	// canonical 16-byte base64 SS2022 EIH uPSK secrets. Encrypted at rest only.
	RelayPoolCredentials map[string]string `json:"relayPoolCredentials,omitempty"`

	// Grant ID to enrolled landing certificate. Bound by the immutable grant
	// account/entry/exit; captured only after current mutual enrollment proof.
	ManagedRouteLandings map[string]string `json:"managedRouteLandings,omitempty"`

	PrunedEntries      map[string]PrunedEntry       `json:"prunedEntries,omitempty"`
	RetiredLandings    map[string]RetiredLanding    `json:"retiredLandings,omitempty"`
	SubscriptionOrders map[string]SubscriptionOrder `json:"subscriptionOrders,omitempty"`
	// Deleted entries remain disabled and retained for identity and accounting history.
	DeletedRoutes       map[string]bool `json:"deletedRoutes,omitempty"`
	DeletedClientChains map[string]bool `json:"deletedClientChains,omitempty"`

	ClientLandings     map[string]ClientLanding         `json:"clientLandings,omitempty"`
	ClientChains       []ClientChain                    `json:"clientChains,omitempty"`
	SourceSHA256       string                           `json:"sourceSha256"`
	RetainedSource     json.RawMessage                  `json:"retainedSource"`
	Endpoints          []ImportEndpoint                 `json:"endpoints"`
	References         ImportReferences                 `json:"references"`
	Plan               ImportPlan                       `json:"plan"`
	SubscriptionTokens map[string]string                `json:"subscriptionTokens"`
	ProtocolSecrets    map[string]string                `json:"protocolSecrets"`
	HysteriaSecrets    map[string]string                `json:"hysteriaSecrets"`
	ResetSchedules     map[string]ImportResetSchedule   `json:"resetSchedules"`
	TrafficCounters    map[string]ImportTrafficCounters `json:"trafficCounters"`
	Ownership          *BusinessOwnership               `json:"ownership,omitempty"`
}

func (m ImportMaterial) Validate() error {
	source, err := m.sourceHeader()
	if err != nil {
		return err
	}
	return m.validateWithSource(source)
}

// A single validation keeps one checked source header for this call only.
func (m ImportMaterial) validateWithSource(source importSourceHeader) error {
	if err := m.validatePrunedEntries(); err != nil {
		return err
	}
	if m.ServerTransportVersion > CurrentServerTransportVersion || len(m.ServerTransports) > 1000 || len(m.ServerTransports) > 0 && m.ServerTransportVersion == 0 {
		return errors.New("glivela: invalid server transport schema")
	}
	hasPoolFields := len(m.EntryRelayConfigs) > 0 || len(m.RelayPools) > 0 || len(m.PooledRoutes) > 0 || len(m.TwoHopEIHBindings) > 0 || len(m.EIHNodeKeys) > 0 || len(m.RelayPoolCredentials) > 0
	if hasPoolFields && m.ServerTransportVersion != CurrentServerTransportVersion {
		return errors.New("glivela: relay pool state requires current server transport schema")
	}
	if len(m.EntryRelayConfigs) > 1000 || len(m.RelayPools) > 1000 || len(m.PooledRoutes) > 10000 || len(m.TwoHopEIHBindings) > 10000 || len(m.EIHNodeKeys) > 1000 || len(m.RelayPoolCredentials) > 20000 {
		return errors.New("glivela: relay pool inventory limit exceeded")
	}
	retainedLegacyTransports := map[string]bool{}
	for _, route := range m.PooledRoutes {
		if (route.PendingLegacyCutover || route.RetiringLegacyTransport) && route.LegacyTransportID != "" {
			retainedLegacyTransports[route.LegacyTransportID] = true
		}
	}
	for id, resource := range m.ServerTransports {
		if id != resource.ID || resource.Validate() != nil {
			return errors.New("glivela: invalid owned server transport")
		}
		if m.ServerTransportVersion == CurrentServerTransportVersion && (resource.Peer.Relay != nil || resource.RelayListener != nil) && !retainedLegacyTransports[id] {
			return errors.New("glivela: legacy single-relay server transport is not permitted in relay pool schema")
		}
		found := false
		for _, account := range m.Plan.Accounts {
			if account.Account.ID == resource.AccountID {
				for _, c := range account.Credentials {
					found = found || c.EntryID == resource.EntryID && c.Kind == NativeCredential
				}
			}
		}
		if !found {
			return errors.New("glivela: server transport account or entry missing")
		}
	}
	for entryID, cfg := range m.EntryRelayConfigs {
		if !ValidIdentifier(entryID) || cfg.Validate() != nil {
			return errors.New("glivela: invalid entry relay config")
		}
	}
	for poolID, pool := range m.RelayPools {
		if poolID != pool.ID || pool.Validate() != nil {
			return errors.New("glivela: invalid relay pool inventory")
		}
	}
	for nodeID, key := range m.EIHNodeKeys {
		if nodeID != key.NodeID || key.Validate() != nil {
			return errors.New("glivela: invalid EIH node key inventory")
		}
	}
	for credID, secret := range m.RelayPoolCredentials {
		if !ValidIdentifier(credID) || !ValidSS2022Key16(secret) {
			return errors.New("glivela: invalid relay pool credential")
		}
	}
	for id, binding := range m.TwoHopEIHBindings {
		if id != binding.ID || binding.Validate() != nil || m.RelayPoolCredentials[binding.CredentialID] == "" || m.EIHNodeKeys[binding.EgressID].ServerKey == "" {
			return errors.New("glivela: invalid two-hop EIH binding inventory")
		}
	}
	for grantID, route := range m.PooledRoutes {
		if grantID != route.GrantID || route.Validate() != nil {
			return errors.New("glivela: invalid pooled route inventory")
		}
		if _, hasPool := m.RelayPools[route.RelayPoolID]; !hasPool {
			return errors.New("glivela: pooled route references unknown relay pool")
		}
		if route.PendingLegacyCutover {
			legacyRes, hasLegacy := m.ServerTransports[route.LegacyTransportID]
			if !hasLegacy || legacyRes.Peer.Relay == nil || legacyRes.RelayListener == nil || legacyRes.AccountID != route.AccountID || legacyRes.EntryID != route.EntryID || legacyRes.EgressID != route.EgressID {
				return errors.New("glivela: pending legacy pooled route missing server transport")
			}
		}
		found := false
		for _, account := range m.Plan.Accounts {
			if account.Account.ID != route.AccountID {
				continue
			}
			for _, g := range account.Grants {
				if g.ID != grantID || m.DeletedRoutes[g.ID] || g.EntryID != route.EntryID || g.EgressID != route.EgressID {
					continue
				}
				if route.PendingLegacyCutover {
					if g.ClientChainID == route.LegacyTransportID && g.RelayPoolID == "" {
						found = true
					}
				} else if g.RelayPoolID == route.RelayPoolID && g.ClientChainID == "" {
					found = true
				}
			}
		}
		if !found {
			return errors.New("glivela: pooled route grant missing or mismatched")
		}
	}

	if len(m.RetiredLandings) > 10000 {
		return errors.New("glivela: too many retired landings")
	}
	for id, retired := range m.RetiredLandings {
		_, referenced := m.References.Nodes[id]
		_, shared := m.ClientLandings[id]
		_, hasEIHKey := m.EIHNodeKeys[id]
		_, hasEntryCfg := m.EntryRelayConfigs[id]
		if !ValidIdentifier(id) || !ValidIdentity(retired.CertificateID) || retired.Revision == 0 || retired.HostID != "" && !ValidIdentifier(retired.HostID) || referenced || shared || hasEIHKey || hasEntryCfg {
			return errors.New("glivela: invalid retired landing")
		}
		for _, pool := range m.RelayPools {
			for _, member := range pool.Members {
				if member.NodeID == id || member.CertificateID == retired.CertificateID {
					return errors.New("glivela: retired landing still in relay pool")
				}
			}
		}
		for _, route := range m.PooledRoutes {
			if route.EntryID == id || route.EgressID == id || route.LandingCertificateID == retired.CertificateID {
				return errors.New("glivela: retired landing still in pooled route")
			}
		}
		for _, b := range m.TwoHopEIHBindings {
			if b.EntryID == id || b.EgressID == id {
				return errors.New("glivela: retired landing still in two-hop EIH binding")
			}
		}
		for _, resource := range m.ServerTransports {
			if resource.EntryID == id || resource.EgressID == id || resource.Peer.Relay != nil && resource.Peer.Relay.NodeID == id {
				return errors.New("glivela: retired landing has owned server transports")
			}
		}
		for _, chain := range m.ClientChains {
			if chain.EntryID == id || chain.EgressID == id || chain.Relay != nil && chain.Relay.NodeID == id {
				return errors.New("glivela: retired landing still referenced")
			}
		}
		for _, endpoint := range m.Endpoints {
			if endpoint.Reality.EntryID == id {
				return errors.New("glivela: retired landing is an entry")
			}
		}
		for _, account := range m.Plan.Accounts {
			for _, grant := range account.Grants {
				if grant.EgressID == id || grant.IPv4EgressID == id {
					return errors.New("glivela: retired landing has server routes")
				}
			}
		}
	}
	seenChains, seenPorts := map[string]bool{}, map[string]bool{}
	if len(m.ClientChains) > 1000 {
		return errors.New("glivela: too many client chains")
	}
	for _, c := range m.ClientChains {
		port := c.EgressID + ":" + fmt.Sprint(c.Port)
		deleted := m.DeletedClientChains[c.ID]
		if c.Validate() != nil || c.Shared || seenChains[c.ID] || !deleted && seenPorts[port] || deleted && c.Enabled {
			return errors.New("glivela: invalid client chain inventory")
		}
		relayPort := ""
		if c.Relay != nil {
			relayPort = c.Relay.NodeID + ":" + fmt.Sprint(c.Relay.Port)
			_, shared := m.ClientLandings[c.Relay.NodeID]
			if !deleted && (relayPort == port || seenPorts[relayPort] || shared && c.Relay.Port == 24000) {
				return errors.New("glivela: conflicting client relay port")
			}
		}
		found := false
		for _, a := range m.Plan.Accounts {
			if a.Account.ID == c.AccountID {
				for _, cred := range a.Credentials {
					if cred.EntryID == c.EntryID && cred.Kind == NativeCredential {
						found = true
					}
				}
			}
		}
		if !found {
			return errors.New("glivela: client chain account or entry missing")
		}
		seenChains[c.ID] = true
		if !deleted {
			seenPorts[port] = true
			if relayPort != "" {
				seenPorts[relayPort] = true
			}
		}
	}
	for landingID, shared := range m.ClientLandings {
		key, err := base64.StdEncoding.DecodeString(shared.Key)
		if !ValidIdentifier(landingID) || !ValidIdentifier(shared.AccountID) || err != nil || len(key) != 16 || base64.StdEncoding.EncodeToString(key) != shared.Key {
			return errors.New("glivela: invalid shared client landing")
		}
		found := false
		for _, c := range m.ClientChains {
			if c.EgressID != landingID || m.DeletedClientChains[c.ID] {
				continue
			}
			found = true
			if c.AccountID != shared.AccountID {
				return errors.New("glivela: shared landing cannot span accounts")
			}
			if _, err := m.EffectiveClientChain(c); err != nil {
				return err
			}
		}
		if !found {
			return errors.New("glivela: unreferenced shared client landing")
		}
	}
	for id, deleted := range m.DeletedClientChains {
		if !deleted || !seenChains[id] {
			return errors.New("glivela: invalid deleted client chain")
		}
	}

	if _, err := m.sourceSnapshotHeader(source); err != nil {
		return err
	}
	if m.Ownership != nil {
		if err := m.Ownership.Validate(m.SourceSHA256); err != nil {
			return err
		}
	}
	plan, err := PlanImport(m.Plan.Accounts)
	if err != nil || plan.SHA256 != m.Plan.SHA256 {
		return errors.New("glivela: import inventory differs")
	}
	if err := m.validateAccountState(); err != nil {
		return err
	}
	if len(m.SubscriptionOrders) > len(plan.Accounts) {
		return errors.New("glivela: invalid subscription order accounts")
	}
	for id, order := range m.SubscriptionOrders {
		found := false
		for _, account := range plan.Accounts {
			found = found || account.Account.ID == id
		}
		if !found || order.Validate() != nil {
			return errors.New("glivela: invalid subscription order account")
		}
	}
	credentials, hysteria := 0, 0
	seenDeletedRoutes := make(map[string]bool, len(m.DeletedRoutes))
	for _, item := range plan.Accounts {
		if SubscriptionTokenFingerprint(m.SubscriptionTokens[item.Account.ID]) != item.SubscriptionTokenFingerprint {
			return errors.New("glivela: subscription identity missing or changed")
		}
		for _, grant := range item.Grants {
			if m.DeletedRoutes[grant.ID] {
				if grant.Enabled {
					return errors.New("glivela: deleted route is enabled")
				}
				seenDeletedRoutes[grant.ID] = true
			} else if m.ServerTransportVersion == CurrentServerTransportVersion && grant.ClientChainID != "" {
				pr, ok := m.PooledRoutes[grant.ID]
				if !ok || !pr.PendingLegacyCutover || pr.LegacyTransportID != grant.ClientChainID {
					return errors.New("glivela: active legacy three-hop grant requires pending relay pool migration")
				}
			}
		}
		for _, credential := range item.Credentials {
			credentials++
			material := CredentialMaterial{Credential: credential, ProtocolID: m.ProtocolSecrets[credential.ID], HysteriaAuth: m.HysteriaSecrets[credential.ID], HysteriaIdentity: item.HysteriaIdentities[credential.ID]}
			if material.Validate() != nil {
				return errors.New("glivela: protocol identity missing or changed")
			}
		}
		for id, expected := range item.HysteriaIdentities {
			hysteria++
			if Identity(m.HysteriaSecrets[id]) != expected {
				return errors.New("glivela: Hysteria identity missing or changed")
			}
		}
	}
	for id, deleted := range m.DeletedRoutes {
		if !deleted || !seenDeletedRoutes[id] {
			return errors.New("glivela: invalid deleted route")
		}
	}
	if len(m.SubscriptionTokens) != len(plan.Accounts) || len(m.ProtocolSecrets) != credentials || len(m.HysteriaSecrets) != hysteria {
		return errors.New("glivela: unreferenced import credentials")
	}
	if err := m.validateEndpoints(source); err != nil {
		return err
	}
	return m.validateReferences()
}

// Only the archive identity header is interpreted here. Legacy table formats
// are read by the one-time offline tool, not by the controller or node runtime.
type importSourceHeader struct {
	Origin       string `json:"origin,omitempty"`
	Version      int    `json:"version"`
	Schema       int    `json:"sourceSchema"`
	SnapshotID   string `json:"snapshotId"`
	SourceSHA256 string `json:"sourceSha256"`
}
type importSourceCache struct {
	Digest [32]byte
	Header importSourceHeader
}

func (m ImportMaterial) sourceHeader() (importSourceHeader, error) {
	if len(m.RetainedSource) > maxImportMaterial {
		return importSourceHeader{}, errors.New("glivela: source archive too large")
	}
	digest := sha256.Sum256(m.RetainedSource)
	if m.sourceCache != nil && m.sourceCache.Digest == digest {
		return m.sourceCache.Header, nil
	}
	var h importSourceHeader
	if json.Unmarshal(m.RetainedSource, &h) != nil {
		return h, errors.New("glivela: invalid source archive")
	}
	return h, nil
}
func (m *ImportMaterial) cacheSource() error {
	h, err := m.sourceHeader()
	if err != nil {
		return err
	}
	m.sourceCache = &importSourceCache{Digest: sha256.Sum256(m.RetainedSource), Header: h}
	return nil
}
func (m ImportMaterial) sourceSnapshot() (string, error) {
	header, err := m.sourceHeader()
	if err != nil {
		return "", err
	}
	return m.sourceSnapshotHeader(header)
}
func (m ImportMaterial) sourceSnapshotHeader(header importSourceHeader) (string, error) {
	if header.Version != 1 || !((header.Origin == "" && (header.Schema == 113 || header.Schema == 114 || header.Schema == 115 || header.Schema == 116 || header.Schema == 120)) || (header.Origin == "native" && header.Schema == 0 && m.Ownership != nil && m.Ownership.Origin == "native")) || !ValidIdentifier(header.SnapshotID) || !ValidIdentity(m.SourceSHA256) || header.SourceSHA256 != m.SourceSHA256 {
		return "", errors.New("glivela: missing or changed source snapshot identity")
	}
	if m.Ownership != nil && (m.Ownership.Origin == "native") != (header.Origin == "native") {
		return "", errors.New("glivela: business origin mismatch")
	}
	return header.SnapshotID, nil
}

const maxImportMaterial = 64 << 20
const importMaterialContext = "glivela-business-handover-v1"

// SealImportMaterial uses standard authenticated encryption with an externally
// supplied 256-bit transfer key. Nonces come from Go's GCM implementation. The
// authenticated snapshot identifier prevents swapping material between exports.
// Successful decryption is not evidence that the legacy writer is fenced.
func SealImportMaterial(m ImportMaterial, key []byte, snapshotID string) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if source, _ := m.sourceSnapshot(); source != snapshotID {
		return nil, errors.New("glivela: source snapshot differs from transfer identity")
	}
	aead, err := importCipher(key, snapshotID)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > maxImportMaterial {
		return nil, errors.New("glivela: import material too large")
	}
	defer clear(raw)
	return aead.Seal(nil, nil, raw, []byte(importMaterialContext+":"+snapshotID)), nil
}

func OpenImportMaterial(sealed, key []byte, snapshotID string) (ImportMaterial, error) {
	aead, err := importCipher(key, snapshotID)
	if err != nil {
		return ImportMaterial{}, err
	}
	if len(sealed) > maxImportMaterial+aead.Overhead() {
		return ImportMaterial{}, errors.New("glivela: import material too large")
	}
	raw, err := aead.Open(nil, nil, sealed, []byte(importMaterialContext+":"+snapshotID))
	if err != nil {
		return ImportMaterial{}, errors.New("glivela: import authentication failed")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var m ImportMaterial
	var extra any
	if decoder.Decode(&m) != nil || decoder.Decode(&extra) != io.EOF || m.cacheSource() != nil || m.Validate() != nil {
		return ImportMaterial{}, errors.New("glivela: invalid import material")
	}
	if source, _ := m.sourceSnapshot(); source != snapshotID {
		return ImportMaterial{}, errors.New("glivela: source snapshot differs from transfer identity")
	}
	return m, nil
}

func importCipher(key []byte, snapshotID string) (cipher.AEAD, error) {
	if len(key) != 32 || !ValidIdentifier(snapshotID) {
		return nil, errors.New("glivela: transfer key and snapshot identity required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("glivela: invalid transfer key")
	}
	return cipher.NewGCMWithRandomNonce(block)
}
