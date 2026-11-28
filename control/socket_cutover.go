package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

const socketCutoversFile = "socket-cutovers.json"

// SocketCutoverConsumer identifies one dialer (two-hop, legacy three-hop,
// pooled landing, or pooled relay ingress) sharing an occupied port 24000 socket.
type SocketCutoverConsumer struct {
	Kind              string `json:"kind"` // "two-hop-source", "two-hop-transport", "legacy-three-hop-landing", "legacy-three-hop-relay", "pooled-route-landing", or "pooled-route-relay"
	EntryID           string `json:"entryId"`
	EntryCertID       string `json:"entryCertificateId"`
	PeerKey           string `json:"peerKey,omitempty"`
	Source            string `json:"source,omitempty"`
	EgressIP          string `json:"egressIp,omitempty"`
	UDP               bool   `json:"udp,omitempty"`
	ServerTransportID string `json:"serverTransportId,omitempty"`
	GrantID           string `json:"grantId,omitempty"`
	CredentialID      string `json:"credentialId,omitempty"`
	BindingID         string `json:"bindingId,omitempty"`
}

// SocketCutoverTargetRollback stores only the exact single-user socket fields
// removed from the target landing so rollback never clobbers unrelated edits.
type SocketCutoverTargetRollback struct {
	HadServerTransport bool                     `json:"hadServerTransport,omitempty"`
	OldTransport       glivela.PrivateTransport `json:"oldTransport,omitzero"`
	RemovedSources     []landing.Source         `json:"removedSources,omitempty"`
	RemovedClients     []landing.ClientListener `json:"removedClients,omitempty"`
	RemovedUDPList     []string                 `json:"removedUdpListeners,omitempty"`
}

// SocketCutoverPeerRollback stores only the exact two-hop peer fields modified
// on one consumer entry so rollback never clobbers concurrent cutovers or grants.
type SocketCutoverPeerRollback struct {
	EntryID           string                   `json:"entryId"`
	EntryCertID       string                   `json:"entryCertificateId"`
	PeerKey           string                   `json:"peerKey"`
	EgressID          string                   `json:"egressId"`
	Port              int                      `json:"port"`
	Transport         glivela.PrivateTransport `json:"transport"`
	ServerTransportID string                   `json:"serverTransportId,omitempty"`
	OldListenerKey    string                   `json:"oldListenerKey,omitempty"`
}

type SocketCutoverRollback struct {
	Target SocketCutoverTargetRollback `json:"target"`
	Peers  []SocketCutoverPeerRollback `json:"peers,omitempty"`
}

type SocketCutoverExpectedReceipt struct {
	Revision     uint64 `json:"revision,string"`
	ConfigSHA256 string `json:"configSha256"`
}

// SocketCutover tracks one Option A controlled cutover window for an occupied
// single-user port 24000 socket transitioning to multi-user SS2022 EIH 24000.
// Write-ahead phases ("starting", "listener-pending", "entries-applying",
// "entries-pending", "rollback-applying", "rollback-pending") enable crash-safe
// idempotent recovery and online retry on controller restart or write failure.
type SocketCutover struct {
	ID                        string                                  `json:"id"`
	TargetNodeID              string                                  `json:"targetNodeId"`
	TargetCertID              string                                  `json:"targetCertificateId"`
	Address                   string                                  `json:"address"`
	Port                      int                                     `json:"port"`
	Phase                     string                                  `json:"phase"`
	CreatedAt                 time.Time                               `json:"createdAt"`
	ListenerRevision          uint64                                  `json:"listenerRevision,string,omitempty"`
	ListenerConfigSHA256      string                                  `json:"listenerConfigSha256,omitempty"`
	FinalListenerRevision     uint64                                  `json:"finalListenerRevision,string,omitempty"`
	FinalListenerConfigSHA256 string                                  `json:"finalListenerConfigSha256,omitempty"`
	EntryReceipts             map[string]SocketCutoverExpectedReceipt `json:"entryReceipts,omitempty"`
	RollbackListener          *SocketCutoverExpectedReceipt           `json:"rollbackListener,omitempty"`
	RollbackTargetEntries     []string                                `json:"rollbackTargetEntries,omitempty"`
	RollbackEntries           map[string]SocketCutoverExpectedReceipt `json:"rollbackEntries,omitempty"`
	// PendingServerKey and PendingSecrets are retained in private 0600 cutover
	// intent ONLY during Phase=="starting" for deterministic crash replay and
	// cleared as soon as Phase transitions to "listener-pending".
	PendingServerKey string                  `json:"pendingServerKey,omitempty"`
	PendingSecrets   map[string]string       `json:"pendingSecrets,omitempty"`
	Consumers        []SocketCutoverConsumer `json:"consumers"`
	Rollback         SocketCutoverRollback   `json:"rollback"`
}

type socketCutoverState struct {
	Version  int                      `json:"version"`
	Cutovers map[string]SocketCutover `json:"cutovers"`
}

type SocketCutoverPlan struct {
	TargetNodeID      string                  `json:"targetNodeId"`
	Address           string                  `json:"address"`
	Port              int                     `json:"port"`
	Occupied          bool                    `json:"occupied"`
	Deferred          bool                    `json:"deferred"`
	BlockingConsumers []string                `json:"blockingConsumers"`
	Consumers         []SocketCutoverConsumer `json:"consumers"`
}

type SocketCutoverView struct {
	ID               string   `json:"id"`
	TargetNodeID     string   `json:"targetNodeId"`
	Address          string   `json:"address"`
	Port             int      `json:"port"`
	Phase            string   `json:"phase"`
	ListenerRevision uint64   `json:"listenerRevision,string"`
	ListenerApplied  bool     `json:"listenerApplied"`
	PendingEntries   []string `json:"pendingEntries"`
	ConsumerEntryIDs []string `json:"consumerEntryIds"`
	Completed        bool     `json:"completed,omitempty"`
	RolledBack       bool     `json:"rolledBack,omitempty"`
}

type SocketCutoverRequest struct {
	Action                 string `json:"action"` // "inspect", "start", "advance", "rollback", "cutover-legacy"
	CutoverID              string `json:"cutoverId,omitempty"`
	TargetNodeID           string `json:"targetNodeId,omitempty"`
	Address                string `json:"address,omitempty"`
	GrantID                string `json:"grantId,omitempty"`
	ExpectedTargetRevision uint64 `json:"expectedTargetRevision,string,omitempty"`
}

func socketCutoverID(targetNodeID, address string) string {
	sum := sha256.Sum256([]byte(targetNodeID + "\x00" + address))
	return "cutover-" + hex.EncodeToString(sum[:12])
}

func cutoverConsumerMigratable(kind string) bool {
	return kind == "two-hop-source" || kind == "two-hop-transport" || kind == "legacy-three-hop-landing"
}

func landingSupportsEIH(node Node, now time.Time) bool {
	return node.Desired.Landing != nil && runtimeFresh(node, now) && node.Receipt != nil && node.MaxLandingRenderVersion >= landing.RenderVersion
}

func entryKnownRelayPoolCapable(node Node) bool {
	return node.Desired.Entry != nil && node.MaxEntryRenderVersion >= glivela.XrayRenderVersion
}

func entrySupportsRelayPool(node Node, now time.Time) bool {
	return entryKnownRelayPoolCapable(node) && runtimeFresh(node, now) && node.Receipt != nil
}

func receiptMatchesExact(node Node, want SocketCutoverExpectedReceipt, now time.Time) bool {
	return runtimeFresh(node, now) && node.Receipt != nil &&
		node.Receipt.Revision == want.Revision &&
		node.Receipt.ConfigSHA256 == want.ConfigSHA256
}

func (s *Store) cutoverHook(step string) error {
	if s.cutoverFaultHook != nil {
		return s.cutoverFaultHook(step)
	}
	return nil
}

func (s *Store) loadSocketCutovers() error {
	path := filepath.Join(filepath.Dir(s.path), socketCutoversFile)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		s.socketCutovers = map[string]SocketCutover{}
		return nil
	}
	raw, err := privateBackupBytes(path)
	var state socketCutoverState
	if err != nil || len(raw) > maxMessage || decode(bytes.NewReader(raw), &state) != nil || state.Version != 1 {
		return errors.New("control: socket cutover state requires recovery")
	}
	for id, c := range state.Cutovers {
		validPhase := c.Phase == "starting" || c.Phase == "listener-pending" || c.Phase == "entries-applying" || c.Phase == "entries-pending" || c.Phase == "rollback-applying" || c.Phase == "rollback-pending"
		if id != c.ID || !glivela.ValidIdentifier(c.ID) || !glivela.ValidIdentifier(c.TargetNodeID) || !glivela.ValidIdentity(c.TargetCertID) || c.Port != glivela.RelayPoolPort || !validPhase {
			return errors.New("control: invalid socket cutover record")
		}
		if (c.Phase == "listener-pending" || c.Phase == "entries-applying" || c.Phase == "entries-pending") && (c.ListenerRevision == 0 || !glivela.ValidIdentity(c.ListenerConfigSHA256)) {
			return errors.New("control: invalid active socket cutover receipt")
		}
		if c.Phase == "entries-pending" && (c.FinalListenerRevision == 0 || !glivela.ValidIdentity(c.FinalListenerConfigSHA256)) {
			return errors.New("control: invalid entries-pending cutover receipt")
		}
		if c.Phase == "rollback-pending" && (c.RollbackListener == nil || c.RollbackListener.Revision == 0 || !glivela.ValidIdentity(c.RollbackListener.ConfigSHA256)) {
			return errors.New("control: invalid rollback-pending cutover receipt")
		}
	}
	if state.Cutovers == nil {
		state.Cutovers = map[string]SocketCutover{}
	}
	s.socketCutovers = state.Cutovers
	return nil
}

func (s *Store) saveSocketCutoversLocked(next map[string]SocketCutover) error {
	directory := filepath.Dir(s.path)
	if len(next) == 0 {
		if err := os.Remove(filepath.Join(directory, socketCutoversFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := syncBusinessDirectory(directory); err != nil {
			return err
		}
		s.socketCutovers = map[string]SocketCutover{}
		return nil
	}
	state := socketCutoverState{Version: 1, Cutovers: next}
	if err := writeControlState(filepath.Join(directory, socketCutoversFile), state); err != nil {
		return err
	}
	s.socketCutovers = next
	return nil
}

// recoverSocketCutoversLocked replays any interrupted write-ahead cutover
// transition on controller startup so a crash between socket-cutovers.json,
// business.json, and nodes.json never leaves an unbootable or conflicting state.
func (s *Store) recoverSocketCutoversLocked(now time.Time) error {
	if len(s.socketCutovers) == 0 || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return nil
	}
	ids := make([]string, 0, len(s.socketCutovers))
	for id := range s.socketCutovers {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		record, ok := s.socketCutovers[id]
		if !ok {
			continue
		}
		switch record.Phase {
		case "starting":
			if _, err := s.applyCutoverStartLocked(record, now); err != nil {
				return err
			}
		case "entries-applying":
			if err := s.replayCutoverEntriesLocked(record, now); err != nil {
				return err
			}
		case "rollback-applying":
			if err := s.applyCutoverRollbackLocked(record, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// InspectSocketCutover inventories EVERY dialer along physical socket
// (targetNodeID, address:24000) — two-hop sources, two-hop ServerTransports,
// pooled-route landings, AND pooled-route relay ingresses — and defers cutover
// whenever any consumer or target is offline, suspended, in transition, or has
// not yet proven support for EIH/RelayPool rendering formats.
func (s *Store) InspectSocketCutover(targetNodeID, address string) (SocketCutoverPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inspectSocketCutoverLocked(targetNodeID, address, time.Now().UTC())
}

func (s *Store) inspectSocketCutoverLocked(targetNodeID, address string, now time.Time) (SocketCutoverPlan, error) {
	if !glivela.ValidIdentifier(targetNodeID) || !(glivela.PublicTransportIPv4(address) || glivela.PublicTransportIPv6(address)) || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return SocketCutoverPlan{}, errors.New("control: invalid socket cutover target")
	}
	var target Node
	found := false
	for _, n := range s.nodes {
		if n.ID == targetNodeID && n.Desired.Landing != nil {
			target, found = n, true
			break
		}
	}
	if !found || entryRetired(s.business.material, targetNodeID) {
		return SocketCutoverPlan{}, errors.New("control: socket cutover target not enrolled")
	}
	plan := SocketCutoverPlan{
		TargetNodeID:      targetNodeID,
		Address:           address,
		Port:              glivela.RelayPoolPort,
		Occupied:          socketOccupiedBySingleUser(*target.Desired.Landing, address),
		BlockingConsumers: []string{},
		Consumers:         []SocketCutoverConsumer{},
	}
	block := func(id string) {
		if !slices.Contains(plan.BlockingConsumers, id) {
			plan.BlockingConsumers = append(plan.BlockingConsumers, id)
		}
	}
	if !landingSupportsEIH(target, now) || s.suspended(target.ID, now) || target.TransportTail != nil {
		block(target.ID)
	}
	m := s.business.material
	byID := map[string]Node{}
	for _, n := range s.nodes {
		byID[n.ID] = n
	}

	// 1. Inventory two-hop AND legacy three-hop consumers dialing (address, 24000).
	for _, entry := range s.nodes {
		if entry.Desired.Entry == nil || entryRetired(m, entry.ID) {
			continue
		}
		for _, peer := range entry.Desired.Entry.Peers {
			if peer.Relay != nil {
				// Edge A: legacy three-hop relay ingress on (targetNodeID, address:24000).
				// ClientChainRelay uses a single-user key and cannot share EIH directly,
				// so inventory and defer until the legacy three-hop moves off this socket.
				if peer.Relay.NodeID == targetNodeID {
					relayDial := peer.DialTransport()
					if relayDial.Endpoint(peer.Address) == address && relayDial.ListenerPort() == glivela.RelayPoolPort {
						block(entry.ID)
						plan.Consumers = append(plan.Consumers, SocketCutoverConsumer{
							Kind:              "legacy-three-hop-relay",
							EntryID:           entry.ID,
							EntryCertID:       entry.CertificateID,
							PeerKey:           peer.PeerKey(),
							ServerTransportID: peer.Transport.ClientListenerID,
						})
					}
				}
				// Edge B: legacy three-hop downstream landing on (targetNodeID, address:24000).
				// Its final hop PrivateTransport supports EIH <iPSK>:<uPSK> and can
				// migrate in-place alongside (or without) two-hop consumers.
				if peer.EgressID == targetNodeID && peer.Transport.Endpoint(peer.Address) == address && peer.Transport.ListenerPort() == glivela.RelayPoolPort && !strings.Contains(peer.Transport.Key, ":") {
					r, ok := m.ServerTransports[peer.Transport.ClientListenerID]
					if !ok {
						block(entry.ID)
						continue
					}
					if !entrySupportsRelayPool(entry, now) || s.suspended(entry.ID, now) || entry.TransportTail != nil {
						block(entry.ID)
					}
					plan.Consumers = append(plan.Consumers, SocketCutoverConsumer{
						Kind:              "legacy-three-hop-landing",
						EntryID:           entry.ID,
						EntryCertID:       entry.CertificateID,
						PeerKey:           peer.PeerKey(),
						ServerTransportID: r.ID,
						Source:            r.Listener.Source,
						EgressIP:          r.Listener.EgressIP,
						UDP:               slices.Contains(target.Desired.Landing.UDPOverTCPListeners, r.Listener.ID),
					})
				}
				continue
			}
			if peer.EgressID != targetNodeID {
				continue
			}
			dial := peer.DialTransport()
			if dial.Endpoint(peer.Address) != address || dial.ListenerPort() != glivela.RelayPoolPort {
				continue
			}
			if strings.Contains(dial.Key, ":") {
				continue // Already migrated to EIH.
			}
			consumer := SocketCutoverConsumer{
				EntryID:     entry.ID,
				EntryCertID: entry.CertificateID,
				PeerKey:     peer.PeerKey(),
			}
			if peer.Transport.ClientListenerID != "" {
				r, ok := m.ServerTransports[peer.Transport.ClientListenerID]
				if !ok {
					block(entry.ID)
					continue
				}
				consumer.Kind = "two-hop-transport"
				consumer.ServerTransportID = r.ID
				consumer.Source = r.Listener.Source
				consumer.EgressIP = r.Listener.EgressIP
				consumer.UDP = slices.Contains(target.Desired.Landing.UDPOverTCPListeners, r.Listener.ID)
			} else {
				consumer.Kind = "two-hop-source"
				if entry.Desired.EntryNetwork == nil || entry.Desired.EntryNetwork.Source == nil {
					block(entry.ID)
					continue
				}
				srcAddr := entry.Desired.EntryNetwork.Source.Address
				matched := false
				for _, src := range target.Desired.Landing.Sources {
					if src.Address == srcAddr && src.PublicAddress != "" {
						consumer.Source = src.PublicAddress
						consumer.UDP = src.UDPOverTCP
						matched = true
						break
					}
				}
				if !matched {
					block(entry.ID)
					continue
				}
			}
			if !entrySupportsRelayPool(entry, now) || s.suspended(entry.ID, now) || entry.TransportTail != nil {
				block(entry.ID)
			}
			plan.Consumers = append(plan.Consumers, consumer)
		}
	}

	// 2. Inventory ALL pooled routes dialing (targetNodeID, address:24000) either
	// as fixed landing OR as relay-pool member ingress.
	_, serverGrants, err := effectiveBusinessCredentials(m, now)
	if err != nil {
		return SocketCutoverPlan{}, err
	}
	for grantID, pr := range m.PooledRoutes {
		if m.DeletedRoutes[grantID] {
			continue
		}
		g, hasGrant := serverGrants[grantID]
		if !hasGrant || !g.Enabled || !g.Route.Enabled {
			continue
		}
		entry, hasEntry := byID[pr.EntryID]
		if pr.EgressID == targetNodeID && pr.LandingAddress == address {
			if !hasEntry || !entrySupportsRelayPool(entry, now) || s.suspended(entry.ID, now) || entry.TransportTail != nil {
				block(pr.EntryID)
			}
			plan.Consumers = append(plan.Consumers, SocketCutoverConsumer{
				Kind:        "pooled-route-landing",
				EntryID:     pr.EntryID,
				EntryCertID: entry.CertificateID,
				GrantID:     grantID,
			})
		}
		pool, hasPool := m.RelayPools[pr.RelayPoolID]
		if !hasPool || !hasEntry || entry.Desired.Entry == nil {
			continue
		}
		cfg := entryEffectiveRelayConfig(entry, m)
		for _, member := range pool.Members {
			if member.NodeID != targetNodeID || member.IsDrained(now) {
				continue
			}
			_, relayIngress, _, _, _, compat := resolveRelayMemberHops(entry, cfg, member, pr)
			if !compat || relayIngress != address {
				continue
			}
			if !entrySupportsRelayPool(entry, now) || s.suspended(entry.ID, now) || entry.TransportTail != nil {
				block(pr.EntryID)
			}
			downstream, hasDownstream := byID[pr.EgressID]
			if !hasDownstream || !landingSupportsEIH(downstream, now) || s.suspended(downstream.ID, now) || downstream.TransportTail != nil {
				block(pr.EgressID)
			}
			plan.Consumers = append(plan.Consumers, SocketCutoverConsumer{
				Kind:        "pooled-route-relay",
				EntryID:     pr.EntryID,
				EntryCertID: entry.CertificateID,
				GrantID:     grantID,
			})
		}
	}
	slices.Sort(plan.BlockingConsumers)
	slices.SortFunc(plan.Consumers, func(a, b SocketCutoverConsumer) int {
		if c := strings.Compare(a.EntryID, b.EntryID); c != 0 {
			return c
		}
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.PeerKey+a.GrantID, b.PeerKey+b.GrantID)
	})
	plan.Deferred = len(plan.BlockingConsumers) > 0
	return plan, nil
}

// StartSocketCutover begins Stage 1 of Option A cutover using write-ahead intent:
// persists Phase=="starting" first, then saves bindings, switches ONLY the
// target listener to EIH 24000, and promotes intent to "listener-pending".
func (s *Store) StartSocketCutover(ctx context.Context, targetNodeID, address string, expectedTargetRevision uint64) (SocketCutoverView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return SocketCutoverView{}, ctx.Err()
	}
	now := time.Now().UTC()
	plan, err := s.inspectSocketCutoverLocked(targetNodeID, address, now)
	if err != nil {
		return SocketCutoverView{}, err
	}
	if !plan.Occupied {
		return SocketCutoverView{}, errors.New("control: socket is not occupied by a single-user 24000 listener")
	}
	if plan.Deferred {
		return SocketCutoverView{}, errors.New("control: socket cutover deferred; unready or incompatible consumer present")
	}
	id := socketCutoverID(targetNodeID, address)
	if _, active := s.socketCutovers[id]; active {
		return SocketCutoverView{}, errors.New("control: socket cutover already in progress")
	}
	var targetCert string
	var target Node
	for cert, n := range s.nodes {
		if n.ID == targetNodeID && n.Desired.Landing != nil {
			targetCert, target = cert, n
			break
		}
	}
	if targetCert == "" || target.Desired.Revision != expectedTargetRevision || target.Desired.Revision == math.MaxUint64 {
		return SocketCutoverView{}, errors.New("control: socket cutover target revision mismatch")
	}

	m := s.business.material
	serverKey := m.EIHNodeKeys[targetNodeID].ServerKey
	if serverKey == "" {
		serverKey, err = randomSS2022Key16()
		if err != nil {
			return SocketCutoverView{}, err
		}
	} else if m.EIHNodeKeys[targetNodeID].CertificateID != targetCert {
		return SocketCutoverView{}, errors.New("control: EIH node server key certificate mismatch")
	}

	consumers := slices.Clone(plan.Consumers)
	pendingSecrets := map[string]string{}
	peerRollbacks := []SocketCutoverPeerRollback{}
	removedSources := map[string]bool{}
	removedClients := map[string]bool{}
	migratableCount := 0
	for i := range consumers {
		c := &consumers[i]
		if !cutoverConsumerMigratable(c.Kind) {
			continue
		}
		migratableCount++
		entry := s.nodes[c.EntryCertID]
		credID := twoHopEIHCredentialID(c.EntryID, targetNodeID, address, c.Source, c.EgressIP, c.UDP)
		secret := m.RelayPoolCredentials[credID]
		if secret == "" {
			if existing, ok := pendingSecrets[credID]; ok {
				secret = existing
			} else {
				secret, err = randomSS2022Key16()
				if err != nil {
					return SocketCutoverView{}, err
				}
			}
		}
		pendingSecrets[credID] = secret
		bindID := twoHopEIHBindingID(c.EntryID, targetNodeID, address, c.ServerTransportID)
		c.CredentialID = credID
		c.BindingID = bindID
		for _, peer := range entry.Desired.Entry.Peers {
			if peer.PeerKey() == c.PeerKey && peer.EgressID == targetNodeID {
				prb := SocketCutoverPeerRollback{
					EntryID:           c.EntryID,
					EntryCertID:       c.EntryCertID,
					PeerKey:           c.PeerKey,
					EgressID:          targetNodeID,
					Port:              peer.Port,
					Transport:         peer.Transport,
					ServerTransportID: c.ServerTransportID,
				}
				if c.ServerTransportID != "" {
					if r, ok := m.ServerTransports[c.ServerTransportID]; ok {
						prb.OldListenerKey = r.Listener.Key
						removedClients[r.Listener.ID] = true
					}
				} else {
					removedSources[c.Source] = true
				}
				peerRollbacks = append(peerRollbacks, prb)
				break
			}
		}
	}
	if migratableCount == 0 {
		return SocketCutoverView{}, errors.New("control: no migratable consumers on occupied socket")
	}

	targetPlan := *target.Desired.Landing
	targetRollback := SocketCutoverTargetRollback{}
	if targetPlan.HasServerListener() && targetPlan.Transport.Endpoint(targetPlan.Address) == address && targetPlan.Transport.ListenerPort() == glivela.RelayPoolPort {
		targetRollback.HadServerTransport = true
		targetRollback.OldTransport = targetPlan.Transport
		for _, src := range targetPlan.Sources {
			if removedSources[src.PublicAddress] {
				targetRollback.RemovedSources = append(targetRollback.RemovedSources, src)
			}
		}
	}
	for _, cl := range targetPlan.ClientListeners {
		cAddr := targetPlan.Transport.PublicAddress
		if cl.Transport == "ipv6-ss2022" || cl.Interface != "" {
			cAddr = cl.Address
		}
		if removedClients[cl.ID] || (cAddr == address && cl.Port == glivela.RelayPoolPort) {
			targetRollback.RemovedClients = append(targetRollback.RemovedClients, cl)
			if slices.Contains(targetPlan.UDPOverTCPListeners, cl.ID) {
				targetRollback.RemovedUDPList = append(targetRollback.RemovedUDPList, cl.ID)
			}
		}
	}

	record := SocketCutover{
		ID:               id,
		TargetNodeID:     targetNodeID,
		TargetCertID:     targetCert,
		Address:          address,
		Port:             glivela.RelayPoolPort,
		Phase:            "starting",
		CreatedAt:        now,
		EntryReceipts:    map[string]SocketCutoverExpectedReceipt{},
		PendingServerKey: serverKey,
		PendingSecrets:   pendingSecrets,
		Consumers:        consumers,
		Rollback: SocketCutoverRollback{
			Target: targetRollback,
			Peers:  peerRollbacks,
		},
	}

	// Pre-validate candidate business material AND target landing plan BEFORE
	// persisting write-ahead "starting" intent so invalid plans never wedge startup.
	if _, _, _, _, err := s.prepareCutoverStartLocked(record, now); err != nil {
		return SocketCutoverView{}, err
	}

	// Write-ahead Step 1: persist "starting" intent BEFORE touching business.json or nodes.json.
	nextCutovers := maps.Clone(s.socketCutovers)
	if nextCutovers == nil {
		nextCutovers = map[string]SocketCutover{}
	}
	nextCutovers[id] = record
	if err := s.saveSocketCutoversLocked(nextCutovers); err != nil {
		return SocketCutoverView{}, err
	}
	if err := s.cutoverHook("start-after-intent"); err != nil {
		return SocketCutoverView{}, err
	}
	return s.applyCutoverStartLocked(record, now)
}

func buildCutoverTargetDesired(base landing.Plan, address, serverKey string, eihUsers []landing.EIHUser, removedSourceIPs, removedClientIDs map[string]bool) (Desired, error) {
	targetPlan := base
	targetPlan.ClientListeners = slices.DeleteFunc(slices.Clone(targetPlan.ClientListeners), func(cl landing.ClientListener) bool {
		cAddr := targetPlan.Transport.PublicAddress
		if cl.Transport == "ipv6-ss2022" || cl.Interface != "" {
			cAddr = cl.Address
		}
		return removedClientIDs[cl.ID] || (cAddr == address && cl.Port == glivela.RelayPoolPort)
	})
	if len(targetPlan.ClientListeners) == 0 {
		targetPlan.ClientListeners = nil
	}
	targetPlan.UDPOverTCPListeners = slices.DeleteFunc(slices.Clone(targetPlan.UDPOverTCPListeners), func(lid string) bool {
		return !slices.ContainsFunc(targetPlan.ClientListeners, func(cl landing.ClientListener) bool { return cl.ID == lid })
	})
	if len(targetPlan.UDPOverTCPListeners) == 0 {
		targetPlan.UDPOverTCPListeners = nil
	}
	if targetPlan.HasServerListener() && targetPlan.Transport.Endpoint(targetPlan.Address) == address && targetPlan.Transport.ListenerPort() == glivela.RelayPoolPort {
		targetPlan.Sources = slices.DeleteFunc(slices.Clone(targetPlan.Sources), func(src landing.Source) bool { return removedSourceIPs[src.PublicAddress] })
		if len(targetPlan.Sources) == 0 {
			targetPlan.Sources = nil
		}
		targetPlan.Transport.Port = 0
		// Retain Transport.PublicAddress (with Port==0) whenever other
		// ClientListeners (e.g. IPv6 24001) still depend on the public binding.
		if len(targetPlan.Sources) == 0 && len(targetPlan.ClientListeners) == 0 {
			targetPlan.Transport = glivela.PrivateTransport{}
		}
	}
	existingEIH := slices.DeleteFunc(targetPlan.CloneEIHListeners(), func(l landing.EIHListener) bool {
		return l.Address == address && l.Port == glivela.RelayPoolPort
	})
	if len(eihUsers) > 0 {
		targetPlan.EIHListeners = append(existingEIH, landing.EIHListener{
			Address:   address,
			Port:      glivela.RelayPoolPort,
			ServerKey: serverKey,
			Users:     eihUsers,
		})
	} else if len(existingEIH) > 0 {
		targetPlan.EIHListeners = existingEIH
	} else {
		targetPlan.EIHListeners = nil
	}
	if targetPlan.Revision == math.MaxUint64 {
		return Desired{}, errors.New("control: landing revision exhausted")
	}
	targetPlan.Revision++
	return NewDesired(targetPlan)
}

func (s *Store) prepareCutoverStartLocked(record SocketCutover, now time.Time) (glivela.ImportMaterial, string, []landing.EIHUser, Desired, error) {
	target, hasTarget := s.nodes[record.TargetCertID]
	if !hasTarget || target.Desired.Landing == nil {
		return glivela.ImportMaterial{}, "", nil, Desired{}, errors.New("control: socket cutover target missing")
	}
	nextMat := s.business.material
	serverKey := record.PendingServerKey
	if serverKey == "" {
		serverKey = nextMat.EIHNodeKeys[record.TargetNodeID].ServerKey
	}
	if !glivela.ValidSS2022Key16(serverKey) {
		return glivela.ImportMaterial{}, "", nil, Desired{}, errors.New("control: missing cutover server key")
	}
	nextMat.EIHNodeKeys = maps.Clone(nextMat.EIHNodeKeys)
	if nextMat.EIHNodeKeys == nil {
		nextMat.EIHNodeKeys = map[string]glivela.EIHNodeKey{}
	}
	nextMat.EIHNodeKeys[record.TargetNodeID] = glivela.EIHNodeKey{
		NodeID:        record.TargetNodeID,
		CertificateID: record.TargetCertID,
		ServerKey:     serverKey,
	}
	nextMat.RelayPoolCredentials = maps.Clone(nextMat.RelayPoolCredentials)
	if nextMat.RelayPoolCredentials == nil {
		nextMat.RelayPoolCredentials = map[string]string{}
	}
	nextMat.TwoHopEIHBindings = maps.Clone(nextMat.TwoHopEIHBindings)
	if nextMat.TwoHopEIHBindings == nil {
		nextMat.TwoHopEIHBindings = map[string]glivela.TwoHopEIHBinding{}
	}

	_, serverGrants, err := effectiveBusinessCredentials(nextMat, now)
	if err != nil {
		return glivela.ImportMaterial{}, "", nil, Desired{}, err
	}
	eihUsers := []landing.EIHUser{}
	removedClientIDs := map[string]bool{}
	removedSourceIPs := map[string]bool{}
	for _, c := range record.Consumers {
		if !cutoverConsumerMigratable(c.Kind) {
			continue
		}
		secret := nextMat.RelayPoolCredentials[c.CredentialID]
		if secret == "" {
			secret = record.PendingSecrets[c.CredentialID]
		}
		if !glivela.ValidSS2022Key16(secret) {
			return glivela.ImportMaterial{}, "", nil, Desired{}, errors.New("control: missing cutover consumer secret")
		}
		nextMat.RelayPoolCredentials[c.CredentialID] = secret
		binding := glivela.TwoHopEIHBinding{
			ID:              c.BindingID,
			EntryID:         c.EntryID,
			EgressID:        record.TargetNodeID,
			LandingAddress:  record.Address,
			Source:          c.Source,
			CredentialID:    c.CredentialID,
			EgressIP:        c.EgressIP,
			UDP:             c.UDP,
			ServerTransport: c.ServerTransportID,
		}
		nextMat.TwoHopEIHBindings[c.BindingID] = binding
		if c.ServerTransportID != "" {
			removedClientIDs[c.ServerTransportID] = true
		} else {
			removedSourceIPs[c.Source] = true
		}
		active, liveUDP := twoHopEIHBindingActive(s.nodes, nextMat, serverGrants, binding, now)
		if active {
			eihUsers = append(eihUsers, landing.EIHUser{
				ID:       c.CredentialID,
				Email:    eihUserEmail(c.CredentialID),
				Key:      secret,
				Source:   c.Source,
				Role:     "landing",
				UDP:      liveUDP,
				EgressIP: c.EgressIP,
			})
		}
	}
	slices.SortFunc(eihUsers, func(a, b landing.EIHUser) int { return strings.Compare(a.ID, b.ID) })
	if err := nextMat.Validate(); err != nil {
		return glivela.ImportMaterial{}, "", nil, Desired{}, err
	}
	candidateDesired, err := buildCutoverTargetDesired(*target.Desired.clone().Landing, record.Address, serverKey, eihUsers, removedSourceIPs, removedClientIDs)
	if err != nil {
		return glivela.ImportMaterial{}, "", nil, Desired{}, err
	}
	return nextMat, serverKey, eihUsers, candidateDesired, nil
}

// applyCutoverStartLocked idempotently completes Steps 2->3->4 of StartSocketCutover.
// Safe to replay on startup if the controller crashed after any write boundary.
func (s *Store) applyCutoverStartLocked(record SocketCutover, now time.Time) (SocketCutoverView, error) {
	nextMat, serverKey, eihUsers, candidateDesired, err := s.prepareCutoverStartLocked(record, now)
	if err != nil {
		return SocketCutoverView{}, err
	}

	// Step 2: Persist EIH key, credentials, and TwoHopEIHBindings to business.json.
	if err := s.saveOwnedBusinessLocked(nextMat); err != nil {
		return SocketCutoverView{}, err
	}
	if err := s.cutoverHook("start-after-business"); err != nil {
		return SocketCutoverView{}, err
	}

	// Step 3: Switch ONLY target landing's (address, 24000) socket to EIH (idempotent).
	nextNodes := s.copy()
	target := nextNodes[record.TargetCertID]
	alreadySwitched := !socketOccupiedBySingleUser(*target.Desired.Landing, record.Address) &&
		(len(eihUsers) == 0 || slices.ContainsFunc(target.Desired.Landing.EIHListeners, func(l landing.EIHListener) bool {
			return l.Address == record.Address && l.Port == glivela.RelayPoolPort && l.ServerKey == serverKey
		}))
	if !alreadySwitched {
		target.Desired, target.Receipt, target.ReportedAt, target.Checks = candidateDesired, nil, time.Time{}, nil
		if len(target.RouteEntries) > 0 {
			entries := maps.Clone(target.RouteEntries)
			for _, c := range record.Consumers {
				if c.Kind == "two-hop-source" {
					if re, ok := entries[c.EntryID]; ok && re.CertificateID == c.EntryCertID {
						re.EIHAddress = record.Address
						entries[c.EntryID] = re
					}
				}
			}
			target.RouteEntries = entries
		}
		nextNodes[record.TargetCertID] = target
		if err := s.commit(nextNodes); err != nil {
			return SocketCutoverView{}, err
		}
		if err := s.cutoverHook("start-after-nodes"); err != nil {
			return SocketCutoverView{}, err
		}
	}

	// Step 4: Promote write-ahead intent to "listener-pending" and clear temporary secrets.
	finalTarget := s.nodes[record.TargetCertID]
	record.Phase = "listener-pending"
	record.ListenerRevision = finalTarget.Desired.Revision
	record.ListenerConfigSHA256 = finalTarget.Desired.ConfigSHA256
	record.PendingServerKey = ""
	record.PendingSecrets = nil
	nextCutovers := maps.Clone(s.socketCutovers)
	nextCutovers[record.ID] = record
	if err := s.saveSocketCutoversLocked(nextCutovers); err != nil {
		return SocketCutoverView{}, err
	}
	return s.socketCutoverViewLocked(record, now), nil
}

// AdvanceSocketCutover gates Stage 2 on the target listener's exact applied EIH
// receipt, switches all inventoried consumers, and completes ONLY after the
// final listener AND every affected entry (both two-hop and pooled) report exact
// applied receipts matching their current Desired Revision and ConfigSHA256.
func (s *Store) AdvanceSocketCutover(ctx context.Context, cutoverID string) (SocketCutoverView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return SocketCutoverView{}, ctx.Err()
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return SocketCutoverView{}, errors.New("control: owned business unavailable")
	}
	record, ok := s.socketCutovers[cutoverID]
	if !ok {
		return SocketCutoverView{}, errors.New("control: socket cutover not found")
	}
	now := time.Now().UTC()
	if record.Phase == "starting" {
		return s.applyCutoverStartLocked(record, now)
	}
	if record.Phase == "rollback-applying" {
		if err := s.applyCutoverRollbackLocked(record, now); err != nil {
			return SocketCutoverView{}, err
		}
		if updated, active := s.socketCutovers[record.ID]; active {
			view := s.socketCutoverViewLocked(updated, now)
			view.RolledBack = true
			return view, nil
		}
		return SocketCutoverView{
			ID:               record.ID,
			TargetNodeID:     record.TargetNodeID,
			Address:          record.Address,
			Port:             record.Port,
			Phase:            "rolled-back",
			ListenerRevision: s.nodes[record.TargetCertID].Desired.Revision,
			ListenerApplied:  true,
			PendingEntries:   []string{},
			ConsumerEntryIDs: []string{},
			RolledBack:       true,
		}, nil
	}
	if record.Phase == "rollback-pending" {
		return s.checkRollbackCompletionLocked(record, now)
	}
	target, hasTarget := s.nodes[record.TargetCertID]
	if !hasTarget || target.ID != record.TargetNodeID || target.Desired.Landing == nil {
		return SocketCutoverView{}, errors.New("control: socket cutover target missing")
	}

	if record.Phase == "listener-pending" {
		wantListener := SocketCutoverExpectedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256}
		if target.Desired.Revision < record.ListenerRevision || socketOccupiedBySingleUser(*target.Desired.Landing, record.Address) || !receiptMatchesExact(target, wantListener, now) {
			return SocketCutoverView{}, errors.New("control: listener EIH receipt pending")
		}
		// Write-ahead Step 1: persist "entries-applying" BEFORE mutating business/nodes
		// so online retry or restart always replays Stage 2 instead of completing early.
		record.Phase = "entries-applying"
		nextCutovers := maps.Clone(s.socketCutovers)
		nextCutovers[record.ID] = record
		if err := s.saveSocketCutoversLocked(nextCutovers); err != nil {
			return SocketCutoverView{}, err
		}
		if err := s.cutoverHook("advance-after-intent"); err != nil {
			return SocketCutoverView{}, err
		}
		if err := s.replayCutoverEntriesLocked(record, now); err != nil {
			return SocketCutoverView{}, err
		}
		return s.socketCutoverViewLocked(s.socketCutovers[record.ID], now), nil
	}

	if record.Phase == "entries-applying" {
		if err := s.replayCutoverEntriesLocked(record, now); err != nil {
			return SocketCutoverView{}, err
		}
		return s.socketCutoverViewLocked(s.socketCutovers[record.ID], now), nil
	}

	// Phase == "entries-pending": verify final listener receipt, ALL affected
	// entry plans actually switched to EIH, exact entry receipts, AND pooled admission.
	if err := s.reconcileOwnedEntriesLocked(now); err != nil {
		return SocketCutoverView{}, err
	}
	record = s.socketCutovers[cutoverID]
	view := s.socketCutoverViewLocked(record, now)
	if !view.ListenerApplied || len(view.PendingEntries) > 0 || !s.cutoverEntriesSwitchedToEIHLocked(record) || !s.cutoverPooledConsumersAdmittedLocked(record, now) {
		return SocketCutoverView{}, errors.New("control: cutover consumer or final listener receipts still pending")
	}
	nextCutovers := maps.Clone(s.socketCutovers)
	delete(nextCutovers, record.ID)
	if err := s.saveSocketCutoversLocked(nextCutovers); err != nil {
		return SocketCutoverView{}, err
	}
	view.Phase = "completed"
	view.Completed = true
	return view, nil
}

func (s *Store) cutoverEntriesSwitchedToEIHLocked(record SocketCutover) bool {
	if record.Phase != "entries-pending" || record.FinalListenerRevision == 0 {
		return false
	}
	m := s.business.material
	serverKey := m.EIHNodeKeys[record.TargetNodeID].ServerKey
	if !glivela.ValidSS2022Key16(serverKey) {
		return false
	}
	for _, c := range record.Consumers {
		if _, hasRec := record.EntryReceipts[c.EntryID]; !hasRec {
			return false
		}
		if !cutoverConsumerMigratable(c.Kind) {
			continue
		}
		entry, ok := s.nodes[c.EntryCertID]
		if !ok || entry.Desired.Entry == nil {
			return false
		}
		secret := m.RelayPoolCredentials[c.CredentialID]
		if !glivela.ValidSS2022Key16(secret) {
			return false
		}
		wantPass := serverKey + ":" + secret
		matched := false
		for _, p := range entry.Desired.Entry.Peers {
			if p.PeerKey() == c.PeerKey && p.EgressID == record.TargetNodeID {
				matched = p.Port == glivela.RelayPoolPort && p.Transport.Protocol == "ss2022" && p.Transport.PublicAddress == record.Address && p.Transport.Port == glivela.RelayPoolPort && p.Transport.Key == wantPass
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// replayCutoverEntriesLocked idempotently applies Stage 2 (two-hop EIH peer
// switch + pooled projection) and records exact expected final revisions/SHAs.
func (s *Store) replayCutoverEntriesLocked(record SocketCutover, now time.Time) error {
	nextMat := s.business.material
	serverKey := nextMat.EIHNodeKeys[record.TargetNodeID].ServerKey
	if !glivela.ValidSS2022Key16(serverKey) {
		return errors.New("control: missing listener EIH server key")
	}
	nextNodes := s.copy()
	nextMat.ServerTransports = maps.Clone(nextMat.ServerTransports)
	byEntry := map[string][]SocketCutoverConsumer{}
	for _, c := range record.Consumers {
		if cutoverConsumerMigratable(c.Kind) {
			byEntry[c.EntryCertID] = append(byEntry[c.EntryCertID], c)
		}
	}
	nodesChanged := false
	for entryCert, list := range byEntry {
		entry, exists := nextNodes[entryCert]
		if !exists || entry.Desired.Entry == nil {
			return errors.New("control: cutover consumer entry missing")
		}
		desired := entry.Desired.clone()
		plan := desired.Entry
		entryMutated := false
		for _, c := range list {
			secret := nextMat.RelayPoolCredentials[c.CredentialID]
			if !glivela.ValidSS2022Key16(secret) {
				return errors.New("control: cutover consumer credential missing")
			}
			eihKey := serverKey + ":" + secret
			for i := range plan.Peers {
				if plan.Peers[i].PeerKey() == c.PeerKey && plan.Peers[i].EgressID == record.TargetNodeID {
					if plan.Peers[i].Transport.Protocol != "ss2022" || plan.Peers[i].Transport.PublicAddress != record.Address || plan.Peers[i].Transport.Port != glivela.RelayPoolPort || plan.Peers[i].Transport.Key != eihKey || plan.Peers[i].Port != glivela.RelayPoolPort {
						plan.Peers[i].Transport.Protocol = "ss2022"
						plan.Peers[i].Transport.PublicAddress = record.Address
						plan.Peers[i].Transport.Port = glivela.RelayPoolPort
						plan.Peers[i].Transport.Key = eihKey
						plan.Peers[i].Port = glivela.RelayPoolPort
						entryMutated = true
					}
				}
			}
			if c.ServerTransportID != "" {
				if r, exists := nextMat.ServerTransports[c.ServerTransportID]; exists {
					r.Peer.Transport.Key = eihKey
					r.Listener.Key = eihKey
					nextMat.ServerTransports[c.ServerTransportID] = r
				}
			}
		}
		if entryMutated {
			if plan.Revision == math.MaxUint64 {
				return errors.New("control: entry revision exhausted")
			}
			plan.Revision++
			updated, err := newEntryDesiredVersion(*plan, *desired.EntryNetwork, glivela.XrayRenderVersion)
			if err != nil {
				return err
			}
			entry.Desired, entry.Receipt, entry.ReportedAt, entry.EntryHealthBarrierAt = updated, nil, time.Time{}, time.Time{}
			nextNodes[entryCert] = entry
			invalidateEntryChecks(nextNodes, entry.ID)
			nodesChanged = true
		}
	}

	nextCutovers := maps.Clone(s.socketCutovers)
	nextCutovers[record.ID] = record
	poolChanged, err := projectRelayPools(nextNodes, nextMat, now, func(id string) bool { return s.suspended(id, now) }, nextCutovers)
	if err != nil {
		return err
	}
	if err := s.saveOwnedBusinessLocked(nextMat); err != nil {
		return err
	}
	if err := s.cutoverHook("advance-after-business"); err != nil {
		return err
	}
	if nodesChanged || poolChanged {
		if err := s.commit(nextNodes); err != nil {
			return err
		}
	}

	// Snapshot exact final listener and ALL consumer entry expected receipts and
	// promote write-ahead intent from "entries-applying" -> "entries-pending".
	finalTarget := s.nodes[record.TargetCertID]
	record.Phase = "entries-pending"
	record.FinalListenerRevision = finalTarget.Desired.Revision
	record.FinalListenerConfigSHA256 = finalTarget.Desired.ConfigSHA256
	entryReceipts := map[string]SocketCutoverExpectedReceipt{}
	for _, c := range record.Consumers {
		if entry, exists := s.nodes[c.EntryCertID]; exists && entry.Desired.Entry != nil {
			entryReceipts[entry.ID] = SocketCutoverExpectedReceipt{
				Revision:     entry.Desired.Revision,
				ConfigSHA256: entry.Desired.ConfigSHA256,
			}
		}
	}
	record.EntryReceipts = entryReceipts
	nextCutovers = maps.Clone(s.socketCutovers)
	nextCutovers[record.ID] = record
	return s.saveSocketCutoversLocked(nextCutovers)
}

// cutoverPooledConsumersAdmittedLocked verifies that every active pooled-route
// consumer inventoried on this socket has actually admitted its candidate onto
// its entry before reporting completion.
func (s *Store) cutoverPooledConsumersAdmittedLocked(record SocketCutover, now time.Time) bool {
	m := s.business.material
	_, serverGrants, err := effectiveBusinessCredentials(m, now)
	if err != nil {
		return false
	}
	for _, c := range record.Consumers {
		if c.Kind != "pooled-route-landing" && c.Kind != "pooled-route-relay" {
			continue
		}
		if m.DeletedRoutes[c.GrantID] {
			continue
		}
		g, ok := serverGrants[c.GrantID]
		if !ok || !g.Enabled || !g.Route.Enabled {
			continue
		}
		pr, hasPR := m.PooledRoutes[c.GrantID]
		if !hasPR || pr.PendingLegacyCutover {
			continue
		}
		entry, hasEntry := s.nodes[c.EntryCertID]
		if !hasEntry || entry.Desired.Entry == nil {
			return false
		}
		var ep *glivela.EntryRelayPool
		for i := range entry.Desired.Entry.RelayPools {
			if entry.Desired.Entry.RelayPools[i].Key == g.PoolKey() {
				ep = &entry.Desired.Entry.RelayPools[i]
				break
			}
		}
		if ep == nil {
			return false
		}
		if c.Kind == "pooled-route-landing" {
			pool := m.RelayPools[pr.RelayPoolID]
			hasEligibleRelay := false
			for _, member := range pool.Members {
				if !member.IsDrained(now) && !s.suspended(member.NodeID, now) {
					hasEligibleRelay = true
					break
				}
			}
			if hasEligibleRelay && !slices.ContainsFunc(ep.Candidates, func(cand glivela.EntryPoolCandidate) bool {
				return cand.LandingAddress == record.Address && cand.LandingPort == glivela.RelayPoolPort
			}) {
				return false
			}
		} else if c.Kind == "pooled-route-relay" {
			pool := m.RelayPools[pr.RelayPoolID]
			eligible := false
			for _, member := range pool.Members {
				if member.NodeID == record.TargetNodeID && !member.IsDrained(now) && !s.suspended(member.NodeID, now) {
					eligible = true
					break
				}
			}
			if eligible && !slices.ContainsFunc(ep.Candidates, func(cand glivela.EntryPoolCandidate) bool {
				return cand.RelayNodeID == record.TargetNodeID
			}) {
				return false
			}
		}
	}
	return true
}

// RollbackSocketCutover initiates or checks receipt completion of a targeted
// delta rollback for THIS cutover only, using strictly higher monotonic
// revisions without overwriting concurrent changes to unrelated grants/cutovers.
func (s *Store) RollbackSocketCutover(ctx context.Context, cutoverID string) (SocketCutoverView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return SocketCutoverView{}, ctx.Err()
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return SocketCutoverView{}, errors.New("control: owned business unavailable")
	}
	record, ok := s.socketCutovers[cutoverID]
	if !ok {
		return SocketCutoverView{}, errors.New("control: socket cutover not found")
	}
	now := time.Now().UTC()
	if record.Phase == "rollback-pending" {
		return s.checkRollbackCompletionLocked(record, now)
	}
	if record.Phase == "rollback-applying" {
		if err := s.applyCutoverRollbackLocked(record, now); err != nil {
			return SocketCutoverView{}, err
		}
		updated, stillActive := s.socketCutovers[record.ID]
		if !stillActive {
			return SocketCutoverView{
				ID:               record.ID,
				TargetNodeID:     record.TargetNodeID,
				Address:          record.Address,
				Port:             record.Port,
				Phase:            "rolled-back",
				ListenerRevision: s.nodes[record.TargetCertID].Desired.Revision,
				ListenerApplied:  true,
				PendingEntries:   []string{},
				ConsumerEntryIDs: []string{},
				RolledBack:       true,
			}, nil
		}
		view := s.socketCutoverViewLocked(updated, now)
		view.RolledBack = true
		return view, nil
	}

	// Determine affected entries BEFORE mutating any node so a crash between
	// nodes.json and socket-cutovers.json cannot lose required rollback receipts.
	rollbackTargetEntries := []string{}
	if record.Phase == "entries-applying" || record.Phase == "entries-pending" {
		for _, c := range record.Consumers {
			if !slices.Contains(rollbackTargetEntries, c.EntryID) {
				rollbackTargetEntries = append(rollbackTargetEntries, c.EntryID)
			}
		}
	}
	slices.Sort(rollbackTargetEntries)

	// Write-ahead Step 1: mark Phase=="rollback-applying" BEFORE touching nodes or business.
	record.Phase = "rollback-applying"
	record.RollbackTargetEntries = rollbackTargetEntries
	record.RollbackListener = nil
	record.RollbackEntries = nil
	record.PendingServerKey = ""
	record.PendingSecrets = nil
	nextCutovers := maps.Clone(s.socketCutovers)
	nextCutovers[record.ID] = record
	if err := s.saveSocketCutoversLocked(nextCutovers); err != nil {
		return SocketCutoverView{}, err
	}
	if err := s.cutoverHook("rollback-after-intent"); err != nil {
		return SocketCutoverView{}, err
	}
	if err := s.applyCutoverRollbackLocked(record, now); err != nil {
		return SocketCutoverView{}, err
	}
	updated, stillActive := s.socketCutovers[record.ID]
	if !stillActive {
		return SocketCutoverView{
			ID:               record.ID,
			TargetNodeID:     record.TargetNodeID,
			Address:          record.Address,
			Port:             record.Port,
			Phase:            "rolled-back",
			ListenerRevision: s.nodes[record.TargetCertID].Desired.Revision,
			ListenerApplied:  true,
			PendingEntries:   []string{},
			ConsumerEntryIDs: []string{},
			RolledBack:       true,
		}, nil
	}
	view := s.socketCutoverViewLocked(updated, now)
	view.RolledBack = true
	return view, nil
}

// applyCutoverRollbackLocked idempotently restores ONLY the exact socket and
// peer fields modified by this cutover onto the CURRENT live plans.
func (s *Store) applyCutoverRollbackLocked(record SocketCutover, now time.Time) error {
	nextNodes := s.copy()
	target, hasTarget := nextNodes[record.TargetCertID]
	if !hasTarget || target.Desired.Landing == nil {
		return errors.New("control: rollback target unavailable")
	}
	nextMat := s.business.material
	serverKey := nextMat.EIHNodeKeys[record.TargetNodeID].ServerKey
	eihKeys := map[string]bool{}
	for _, c := range record.Consumers {
		if c.CredentialID != "" && serverKey != "" {
			if sec := nextMat.RelayPoolCredentials[c.CredentialID]; sec != "" {
				eihKeys[serverKey+":"+sec] = true
			}
		}
	}

	// 1. Targeted delta restore on live target landing plan.
	targetChanged := false
	targetPlan := *target.Desired.clone().Landing
	filteredEIH := slices.DeleteFunc(targetPlan.CloneEIHListeners(), func(l landing.EIHListener) bool {
		return l.Address == record.Address && l.Port == glivela.RelayPoolPort
	})
	if len(filteredEIH) == 0 {
		filteredEIH = nil
	}
	if len(filteredEIH) != len(targetPlan.EIHListeners) {
		targetPlan.EIHListeners = filteredEIH
		targetChanged = true
	}
	if record.Rollback.Target.HadServerTransport {
		if targetPlan.Transport != record.Rollback.Target.OldTransport {
			targetPlan.Transport = record.Rollback.Target.OldTransport
			targetChanged = true
		}
		for _, src := range record.Rollback.Target.RemovedSources {
			if !slices.ContainsFunc(targetPlan.Sources, func(existing landing.Source) bool { return existing.Address == src.Address }) {
				targetPlan.Sources = append(targetPlan.Sources, src)
				targetChanged = true
			}
		}
	}
	for _, cl := range record.Rollback.Target.RemovedClients {
		if !slices.ContainsFunc(targetPlan.ClientListeners, func(existing landing.ClientListener) bool { return existing.ID == cl.ID }) {
			targetPlan.ClientListeners = append(targetPlan.ClientListeners, cl)
			targetChanged = true
		}
	}
	for _, lid := range record.Rollback.Target.RemovedUDPList {
		if !slices.Contains(targetPlan.UDPOverTCPListeners, lid) && slices.ContainsFunc(targetPlan.ClientListeners, func(cl landing.ClientListener) bool { return cl.ID == lid }) {
			targetPlan.UDPOverTCPListeners = append(targetPlan.UDPOverTCPListeners, lid)
			targetChanged = true
		}
	}
	if targetChanged {
		if targetPlan.Revision == math.MaxUint64 {
			return errors.New("control: landing revision exhausted")
		}
		targetPlan.Revision++
		desiredLanding, err := NewDesired(targetPlan)
		if err != nil {
			return err
		}
		target.Desired, target.Receipt, target.ReportedAt, target.Checks = desiredLanding, nil, time.Time{}, nil
	}
	routeEntriesChanged := false
	if record.Rollback.Target.HadServerTransport && len(target.RouteEntries) > 0 {
		entries := maps.Clone(target.RouteEntries)
		for _, c := range record.Consumers {
			if c.Kind == "two-hop-source" {
				if re, ok := entries[c.EntryID]; ok && re.EIHAddress == record.Address {
					re.EIHAddress = ""
					entries[c.EntryID] = re
					routeEntriesChanged = true
				}
			}
		}
		if routeEntriesChanged {
			target.RouteEntries = entries
		}
	}
	if targetChanged || routeEntriesChanged {
		nextNodes[record.TargetCertID] = target
	}

	// 2. Targeted delta restore on live consumer entries (ONLY this cutover's peers!).
	rolledEntries := map[string]bool{}
	nodesChanged := targetChanged || routeEntriesChanged
	for _, prb := range record.Rollback.Peers {
		entry, exists := nextNodes[prb.EntryCertID]
		if !exists || entry.Desired.Entry == nil {
			continue
		}
		desired := entry.Desired.clone()
		plan := desired.Entry
		entryMutated := false
		for i := range plan.Peers {
			if plan.Peers[i].PeerKey() == prb.PeerKey && plan.Peers[i].EgressID == prb.EgressID {
				// Restore ONLY if this peer currently holds this cutover's EIH key
				// (or was partially switched), never touching unrelated peers or grants.
				if strings.Contains(plan.Peers[i].Transport.Key, ":") && (len(eihKeys) == 0 || eihKeys[plan.Peers[i].Transport.Key]) {
					plan.Peers[i].Port = prb.Port
					plan.Peers[i].Transport = prb.Transport
					entryMutated = true
				}
			}
		}
		if entryMutated {
			if plan.Revision == math.MaxUint64 {
				return errors.New("control: entry revision exhausted")
			}
			plan.Revision++
			updated, err := newEntryDesiredVersion(*plan, *desired.EntryNetwork, desired.EntryRenderVersion)
			if err != nil {
				return err
			}
			entry.Desired, entry.Receipt, entry.ReportedAt, entry.EntryHealthBarrierAt = updated, nil, time.Time{}, time.Time{}
			nextNodes[prb.EntryCertID] = entry
			invalidateEntryChecks(nextNodes, entry.ID)
			rolledEntries[entry.ID] = true
			nodesChanged = true
		}
	}

	// 3. Remove ONLY this cutover's bindings and restore ONLY this cutover's ServerTransport keys.
	nextMat.TwoHopEIHBindings = maps.Clone(nextMat.TwoHopEIHBindings)
	for _, c := range record.Consumers {
		if c.BindingID != "" {
			delete(nextMat.TwoHopEIHBindings, c.BindingID)
		}
	}
	if len(nextMat.TwoHopEIHBindings) == 0 {
		nextMat.TwoHopEIHBindings = nil
	}
	for _, prb := range record.Rollback.Peers {
		if prb.ServerTransportID != "" {
			if r, exists := nextMat.ServerTransports[prb.ServerTransportID]; exists {
				nextMat.ServerTransports = maps.Clone(nextMat.ServerTransports)
				r.Peer.Port = prb.Port
				r.Peer.Transport = prb.Transport
				if prb.OldListenerKey != "" {
					r.Listener.Key = prb.OldListenerKey
				}
				nextMat.ServerTransports[prb.ServerTransportID] = r
			}
		}
	}
	cutoversWithoutThis := maps.Clone(s.socketCutovers)
	delete(cutoversWithoutThis, record.ID)
	gcUnreferencedRelayPoolCredentials(&nextMat, nextNodes, cutoversWithoutThis)

	// Re-project live server landing policies (e.g. current UDP flags changed
	// during the cutover window) and pooled routes before committing rollback.
	landingChanged, err := projectServerLandings(nextNodes, nextMat, now, cutoversWithoutThis)
	if err != nil {
		return err
	}
	poolChanged, err := projectRelayPools(nextNodes, nextMat, now, func(id string) bool { return s.suspended(id, now) }, s.socketCutovers)
	if err != nil {
		return err
	}
	if nodesChanged || landingChanged || poolChanged {
		if err := s.commit(nextNodes); err != nil {
			return err
		}
		if err := s.cutoverHook("rollback-after-nodes"); err != nil {
			return err
		}
	}
	if err := s.saveOwnedBusinessLocked(nextMat); err != nil {
		return err
	}

	// 4. Promote from "rollback-applying" -> "rollback-pending" with exact
	// target & entry receipts persisted before clearing on confirmation.
	finalTarget := s.nodes[record.TargetCertID]
	rb := SocketCutoverExpectedReceipt{Revision: finalTarget.Desired.Revision, ConfigSHA256: finalTarget.Desired.ConfigSHA256}
	record.RollbackListener = &rb
	targetEntries := slices.Clone(record.RollbackTargetEntries)
	for entryID := range rolledEntries {
		if !slices.Contains(targetEntries, entryID) {
			targetEntries = append(targetEntries, entryID)
		}
	}
	if poolChanged {
		for _, c := range record.Consumers {
			if !slices.Contains(targetEntries, c.EntryID) {
				targetEntries = append(targetEntries, c.EntryID)
			}
		}
	}
	slices.Sort(targetEntries)
	record.RollbackTargetEntries = targetEntries
	record.RollbackEntries = map[string]SocketCutoverExpectedReceipt{}
	for _, entryID := range targetEntries {
		for _, n := range s.nodes {
			if n.ID == entryID && n.Desired.Entry != nil {
				record.RollbackEntries[entryID] = SocketCutoverExpectedReceipt{
					Revision:     n.Desired.Revision,
					ConfigSHA256: n.Desired.ConfigSHA256,
				}
				break
			}
		}
	}
	record.Phase = "rollback-pending"
	nextCutovers := maps.Clone(s.socketCutovers)
	nextCutovers[record.ID] = record
	if err := s.saveSocketCutoversLocked(nextCutovers); err != nil {
		return err
	}
	// If everything already matched (e.g., crash before target mutated), clear immediately.
	if s.rollbackReceiptsCompleteLocked(s.nodes, record, now) {
		delete(nextCutovers, record.ID)
		return s.saveSocketCutoversLocked(nextCutovers)
	}
	return nil
}

func hasEIHListenerOnSocket(plan landing.Plan, address string) bool {
	return slices.ContainsFunc(plan.EIHListeners, func(l landing.EIHListener) bool {
		return l.Address == address && l.Port == glivela.RelayPoolPort
	})
}

func entryHasRolledBackCutoverPeers(entry Node, record SocketCutover) bool {
	if entry.Desired.Entry == nil {
		return false
	}
	for _, prb := range record.Rollback.Peers {
		if prb.EntryID != entry.ID {
			continue
		}
		for _, p := range entry.Desired.Entry.Peers {
			if p.PeerKey() == prb.PeerKey && p.EgressID == prb.EgressID && strings.Contains(p.Transport.Key, ":") {
				return false
			}
		}
	}
	return true
}

func (s *Store) rollbackReceiptsCompleteLocked(nodes map[string]Node, record SocketCutover, now time.Time) bool {
	if record.Phase != "rollback-pending" || record.RollbackListener == nil {
		return false
	}
	target, ok := nodes[record.TargetCertID]
	if !ok || target.Desired.Landing == nil || target.Desired.Revision < record.RollbackListener.Revision || hasEIHListenerOnSocket(*target.Desired.Landing, record.Address) {
		return false
	}
	wantTarget := SocketCutoverExpectedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256}
	if !receiptMatchesExact(target, wantTarget, now) {
		return false
	}
	for _, entryID := range record.RollbackTargetEntries {
		if _, hasWant := record.RollbackEntries[entryID]; !hasWant {
			return false
		}
	}
	for entryID, want := range record.RollbackEntries {
		matched := false
		for _, n := range nodes {
			if n.ID == entryID && n.Desired.Entry != nil && n.Desired.Revision >= want.Revision && entryHasRolledBackCutoverPeers(n, record) {
				wantEntry := SocketCutoverExpectedReceipt{Revision: n.Desired.Revision, ConfigSHA256: n.Desired.ConfigSHA256}
				if receiptMatchesExact(n, wantEntry, now) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (s *Store) checkRollbackCompletionLocked(record SocketCutover, now time.Time) (SocketCutoverView, error) {
	if !s.rollbackReceiptsCompleteLocked(s.nodes, record, now) {
		view := s.socketCutoverViewLocked(record, now)
		view.RolledBack = true
		return view, nil
	}
	nextCutovers := maps.Clone(s.socketCutovers)
	delete(nextCutovers, record.ID)
	if err := s.saveSocketCutoversLocked(nextCutovers); err != nil {
		return SocketCutoverView{}, err
	}
	rev := uint64(0)
	if record.RollbackListener != nil {
		rev = record.RollbackListener.Revision
	}
	return SocketCutoverView{
		ID:               record.ID,
		TargetNodeID:     record.TargetNodeID,
		Address:          record.Address,
		Port:             record.Port,
		Phase:            "rolled-back",
		ListenerRevision: rev,
		ListenerApplied:  true,
		PendingEntries:   []string{},
		ConsumerEntryIDs: []string{},
		RolledBack:       true,
	}, nil
}

// finalizeRollingBackCutoversLocked removes any "rollback-pending" cutover
// record once its target landing and rolled-back entries have reported receipts.
func (s *Store) finalizeRollingBackCutoversLocked(nodes map[string]Node, now time.Time) error {
	if len(s.socketCutovers) == 0 {
		return nil
	}
	var done []string
	for id, c := range s.socketCutovers {
		if c.Phase == "rollback-pending" && s.rollbackReceiptsCompleteLocked(nodes, c, now) {
			done = append(done, id)
		}
	}
	if len(done) == 0 {
		return nil
	}
	nextCutovers := maps.Clone(s.socketCutovers)
	for _, id := range done {
		delete(nextCutovers, id)
	}
	return s.saveSocketCutoversLocked(nextCutovers)
}

func (s *Store) socketCutoverViewLocked(record SocketCutover, now time.Time) SocketCutoverView {
	rev := record.ListenerRevision
	if record.Phase == "listener-pending" {
		if target, ok := s.nodes[record.TargetCertID]; ok && target.Desired.Revision > rev {
			rev = target.Desired.Revision
		}
	}
	if record.Phase == "entries-pending" && record.FinalListenerRevision > rev {
		rev = record.FinalListenerRevision
	}
	if (record.Phase == "rollback-applying" || record.Phase == "rollback-pending") && record.RollbackListener != nil {
		rev = record.RollbackListener.Revision
		if target, ok := s.nodes[record.TargetCertID]; ok && target.Desired.Revision > rev {
			rev = target.Desired.Revision
		}
	}
	view := SocketCutoverView{
		ID:               record.ID,
		TargetNodeID:     record.TargetNodeID,
		Address:          record.Address,
		Port:             record.Port,
		Phase:            record.Phase,
		ListenerRevision: rev,
		PendingEntries:   []string{},
		ConsumerEntryIDs: []string{},
	}
	if target, ok := s.nodes[record.TargetCertID]; ok && target.Desired.Landing != nil {
		switch record.Phase {
		case "listener-pending":
			want := SocketCutoverExpectedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256}
			view.ListenerApplied = target.Desired.Revision >= record.ListenerRevision && !socketOccupiedBySingleUser(*target.Desired.Landing, record.Address) && receiptMatchesExact(target, want, now)
		case "entries-pending":
			want := SocketCutoverExpectedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256}
			view.ListenerApplied = target.Desired.Revision >= record.FinalListenerRevision && receiptMatchesExact(target, want, now)
		case "rollback-pending":
			if record.RollbackListener != nil && target.Desired.Revision >= record.RollbackListener.Revision && !hasEIHListenerOnSocket(*target.Desired.Landing, record.Address) {
				want := SocketCutoverExpectedReceipt{Revision: target.Desired.Revision, ConfigSHA256: target.Desired.ConfigSHA256}
				view.ListenerApplied = receiptMatchesExact(target, want, now)
			}
		}
	}
	for _, c := range record.Consumers {
		if !slices.Contains(view.ConsumerEntryIDs, c.EntryID) {
			view.ConsumerEntryIDs = append(view.ConsumerEntryIDs, c.EntryID)
		}
	}
	slices.Sort(view.ConsumerEntryIDs)
	if record.Phase == "entries-applying" {
		view.PendingEntries = append(view.PendingEntries, view.ConsumerEntryIDs...)
	} else if record.Phase == "rollback-applying" {
		view.PendingEntries = append(view.PendingEntries, record.RollbackTargetEntries...)
	} else if record.Phase == "rollback-pending" {
		for entryID, want := range record.RollbackEntries {
			applied := false
			for _, n := range s.nodes {
				if n.ID == entryID && n.Desired.Entry != nil && n.Desired.Revision >= want.Revision && entryHasRolledBackCutoverPeers(n, record) {
					wantEntry := SocketCutoverExpectedReceipt{Revision: n.Desired.Revision, ConfigSHA256: n.Desired.ConfigSHA256}
					if receiptMatchesExact(n, wantEntry, now) {
						applied = true
						break
					}
				}
			}
			if !applied {
				view.PendingEntries = append(view.PendingEntries, entryID)
			}
		}
	} else if record.Phase == "entries-pending" {
		// Check every consumer entry against BOTH its recorded expected receipt
		// AND its current live Desired (catches subsequent pooled-admission bumps).
		seen := map[string]bool{}
		for _, c := range record.Consumers {
			if seen[c.EntryID] {
				continue
			}
			seen[c.EntryID] = true
			n, ok := s.nodes[c.EntryCertID]
			if !ok || n.Desired.Entry == nil {
				view.PendingEntries = append(view.PendingEntries, c.EntryID)
				continue
			}
			want := SocketCutoverExpectedReceipt{Revision: n.Desired.Revision, ConfigSHA256: n.Desired.ConfigSHA256}
			if rec, hasRec := record.EntryReceipts[c.EntryID]; hasRec && n.Desired.Revision < rec.Revision {
				view.PendingEntries = append(view.PendingEntries, c.EntryID)
				continue
			}
			if !receiptMatchesExact(n, want, now) {
				view.PendingEntries = append(view.PendingEntries, c.EntryID)
			}
		}
	}
	slices.Sort(view.PendingEntries)
	return view
}

func (s *Store) socketCutoverViewsLocked(now time.Time) []SocketCutoverView {
	views := make([]SocketCutoverView, 0, len(s.socketCutovers))
	for _, c := range s.socketCutovers {
		views = append(views, s.socketCutoverViewLocked(c, now))
	}
	slices.SortFunc(views, func(a, b SocketCutoverView) int { return strings.Compare(a.ID, b.ID) })
	return views
}
