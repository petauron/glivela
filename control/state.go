package control

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	glivela "github.com/petauron/glivela"
)

type Node struct {
	Network             *NetworkSettings `json:"network,omitempty"`
	PrivateListenerPort int              `json:"privateListenerPort,omitempty"`
	// Execution configuration only: never a quota or accounting rollback.
	TransportPrevious    *Desired              `json:"transportPrevious,omitempty"`
	TransportTail        *TransportTail        `json:"transportTail,omitempty"`
	PublicationSuspended bool                  `json:"publicationSuspended,omitempty"`
	AvailabilityRevision uint64                `json:"availabilityRevision,omitempty"`
	EntryQuota           *EntryQuota           `json:"entryQuota,omitempty"`
	RouteEntries         map[string]RouteEntry `json:"routeEntries,omitempty"`
	Checks               map[string]RouteCheck `json:"checks,omitempty"`
	ID                   string                `json:"id"`
	CertificateID        string                `json:"certificateId"`
	Desired              Desired               `json:"desired"`
	Receipt              *Observation          `json:"receipt,omitempty"`
	ReportedAt           time.Time             `json:"reportedAt,omitempty"`
	EntryHealthBarrierAt time.Time             `json:"entryHealthBarrierAt,omitempty"`
}

// Store is a bounded single-process state file for the MVP. Callers must run
// one controller per directory; it is not a multi-writer database protocol.
// Desired entry plans contain sensitive runtime configuration. The node state
// is private (0600) and must never be logged or published. Imported business
// data is separately authenticated/encrypted; node desired plans are projections.
type Store struct {
	mu                  sync.Mutex
	qualityPolls        map[string]time.Time
	quality             *QualityHistory
	path                string
	nodes               map[string]Node
	availability        availabilityState
	business            *businessState
	managementUI        http.Handler
	latencies           map[string]*latencyRecord
	latencyHistory      *latencyHistoryState
	latencyHistoryFault bool
	networkReports      map[string]NetworkSnapshot
	pathMTUNodes        map[string]time.Time
	pathMTUReports      map[string]map[string]PathMTUObservation
	speedJobs           map[string]*speedRecord
	nodeEvents          *nodeEventHub
	speedHub            *speedHub
	speedRevision       uint64
	speedChanged        chan struct{}
	speedFault          bool
	subscriptionNames   map[string]string
	hostBindings        map[string]string
	subscriptionOrigin  string
}

func OpenStore(path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("control: absolute state path required")
	}
	for parent := filepath.Dir(path); parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("control: unsafe state directory")
		}
	}
	s := &Store{path: path, nodes: map[string]Node{}, speedHub: newSpeedHub(), nodeEvents: newNodeEventHub(), speedChanged: make(chan struct{})}
	if err := s.loadHostBindings(); err != nil {
		return nil, err
	}
	if err := s.loadAvailability(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := s.loadSpeedState(); err != nil {
			return nil, err
		}
		if len(s.speedJobs) != 0 {
			return nil, errors.New("control: speed state without enrolled nodes")
		}
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxMessage {
		return nil, errors.New("control: unsafe state file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var nodes []Node
	if json.Unmarshal(raw, &nodes) != nil {
		return nil, errors.New("control: invalid state")
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		if node.TransportPrevious != nil && (node.TransportPrevious.Validate() != nil || node.TransportPrevious.Revision >= node.Desired.Revision || (node.TransportPrevious.Entry == nil) != (node.Desired.Entry == nil)) {
			return nil, errors.New("control: invalid previous transport configuration")
		}
		if node.TransportTail != nil && validateTransportTail(node, node.TransportTail) != nil {
			return nil, errors.New("control: invalid private transport checkpoint")
		}
		if node.AvailabilityRevision > s.availability.Revision {
			return nil, errors.New("control: availability state missing or rolled back")
		}
		if node.EntryQuota != nil && (node.EntryQuota.validate() != nil || node.EntryQuota.validateDesired(node.Desired) != nil) {
			return nil, errors.New("control: invalid stored entry quota")
		}
		if !glivela.ValidIdentifier(node.ID) || !glivela.ValidIdentity(node.CertificateID) || node.Desired.Validate() != nil || seen[node.ID] || validateNodeRole(node) != nil {
			return nil, errors.New("control: invalid node")
		}
		if _, ok := s.nodes[node.CertificateID]; ok {
			return nil, errors.New("control: duplicate enrollment")
		}
		if node.Receipt != nil && glivela.VerifyAppliedReceipt(node.Desired.DesiredArtifact, node.Receipt.AppliedReceipt) != nil {
			return nil, errors.New("control: invalid stored receipt")
		}
		if node.Receipt != nil && validateStoredEntryHealth(node.Desired, node.Receipt.EntryHealth) != nil {
			return nil, errors.New("control: invalid stored entry observation")
		}
		if node.Receipt != nil && validateEntryTraffic(node.Desired, node.Receipt.Traffic) != nil {
			return nil, errors.New("control: invalid stored traffic observation")
		}
		staleChecks := false
		for entry, check := range node.Checks {
			// An older, well-formed attempt cannot prove the current landing.
			// Discard the complete inventory rather than reuse partial results;
			// malformed, future and mismatched current attempts still fail closed.
			outdated := node.Desired.Landing != nil && check.Request.LandingID == node.ID && check.Request.Revision < node.Desired.Revision && check.Request.ConfigSHA256 != node.Desired.ConfigSHA256
			if entry != check.Request.EntryID || !outdated && !routeTargetsLanding(check.Request, node) || check.Request.Validate() != nil || !glivela.ValidIdentity(check.CertificateID) || check.IssuedAt.IsZero() || check.Result != nil && validateRouteResult(check.Request, *check.Result) != nil {
				return nil, errors.New("control: invalid stored route check")
			}
			if len(node.Checks) > 64 || !outdated && (check.Request.Revision != node.Desired.Revision || check.Request.ConfigSHA256 != node.Desired.ConfigSHA256) || (check.Result == nil) != check.ReceivedAt.IsZero() {
				return nil, errors.New("control: inconsistent stored route check")
			}
			staleChecks = staleChecks || outdated
		}
		if staleChecks {
			node.Checks = nil
		}
		seen[node.ID] = true
		s.nodes[node.CertificateID] = node
	}
	retainedDeferred := map[string]bool{}
	for id := range s.effectiveAvailabilities() {
		retainedDeferred[id] = true
	}
	for _, node := range s.nodes {
		if len(node.Checks) > 0 && !completeRouteInventory(node, node.Checks, retainedDeferred) {
			return nil, errors.New("control: incomplete stored entry verification inventory")
		}
	}
	if err := validateEnrollmentRoles(s.nodes); err != nil {
		return nil, err
	}
	if err := s.loadSpeedState(); err != nil {
		return nil, err
	}
	return s, nil
}

// Put is a local controller operation, never exposed on the node HTTP API.
// Stable node identity survives configuration changes. Certificate rotation
// requires the same node ID and atomically revokes the previous certificate.
func (s *Store) Put(node Node) error {
	return s.put(node, "")
}

func (s *Store) put(node Node, previousVerifierCertificate string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entryRetiredLocked(node.ID) {
		return errors.New("control: entry is retired")
	}
	if node.EntryQuota != nil {
		if s.business != nil || node.EntryQuota.validate() != nil || node.EntryQuota.validateDesired(node.Desired) != nil || node.EntryQuota.Raw != nil {
			return errors.New("control: invalid initial staged quota")
		}
		for _, counter := range node.EntryQuota.Forwarded.Counters {
			if counter.Upload != 0 || counter.Download != 0 {
				return errors.New("control: initial forwarded counters must be empty")
			}
		}
	}
	if !glivela.ValidIdentifier(node.ID) || !glivela.ValidIdentity(node.CertificateID) || node.Desired.Validate() != nil || len(node.Checks) != 0 || validateNodeRole(node) != nil {
		return errors.New("control: invalid enrollment")
	}
	next := s.copy()
	if previousVerifierCertificate != "" {
		if err := s.retireLegacyVerifierReferences(next, node, previousVerifierCertificate); err != nil {
			return err
		}
	}
	if existing, ok := next[node.CertificateID]; ok && existing.ID != node.ID {
		return errors.New("control: certificate already assigned")
	}
	for key, old := range next {
		if old.ID != node.ID {
			continue
		}
		if old.EntryQuota != nil {
			return errors.New("control: staged quota enrollment cannot replace retained counters or policy")
		}
		// The administrator-owned listener setting is not an enrollment input.
		node.PrivateListenerPort = old.PrivateListenerPort
		if (old.Desired.Entry == nil) != (node.Desired.Entry == nil) {
			return errors.New("control: changing node role requires explicit handover")
		}
		// Transport identity/probe policy is not encoded in Xray's config hash.
		// Reusing its revision would let the node deduplicate a required gate
		// change and accept a receipt for the previous policy.
		if node.Desired.Revision < old.Desired.Revision || node.Desired.Revision == old.Desired.Revision && (node.Desired.ConfigSHA256 != old.Desired.ConfigSHA256 || !reflect.DeepEqual(node.Desired.EntryNetwork, old.Desired.EntryNetwork)) {
			return errors.New("control: non-monotonic desired state")
		}
		if node.Desired.Revision == old.Desired.Revision && maps.Equal(node.RouteEntries, old.RouteEntries) {
			node.Checks = old.Checks
		}
		if old.Desired.Entry != nil && old.CertificateID != node.CertificateID {
			for peerKey, peer := range next {
				if entry, ok := peer.RouteEntries[node.ID]; ok && entry.CertificateID == old.CertificateID {
					peer.RouteEntries = maps.Clone(peer.RouteEntries)
					entry.CertificateID = node.CertificateID
					peer.RouteEntries[node.ID] = entry
					next[peerKey] = peer
				}
			}
		}
		delete(next, key)
	}
	// Administrative imports cannot manufacture a ready node.
	node.Receipt = nil
	node.EntryHealthBarrierAt = time.Time{}
	node.ReportedAt = time.Time{}
	node.Desired = node.Desired.clone()
	node.EntryQuota = node.EntryQuota.clone()
	node.RouteEntries = maps.Clone(node.RouteEntries)
	next[node.CertificateID] = node
	if node.Desired.Entry != nil {
		invalidateEntryChecks(next, node.ID)
	}
	if err := validateEnrollmentRoles(next); err != nil {
		return err
	}
	if s.business != nil && s.business.material.Ownership != nil {
		if s.business.faulted {
			return errors.New("control: owned business storage requires recovery")
		}
		projected, _, err := projectBusinessEntries(next, s.business.material, time.Now())
		if err != nil {
			return err
		}
		next = projected
	}
	if previousVerifierCertificate != "" {
		for certificate, before := range s.nodes {
			if after, ok := next[certificate]; !ok || !reflect.DeepEqual(before.Desired, after.Desired) {
				return errors.New("control: verifier handover would change another runtime")
			}
		}
	}
	return s.commit(next)
}

// currentDesired reads only the enrolled node's existing policy. In particular,
// a diagnostic must not submit an empty observation: Exchange(nil) deliberately
// clears old health. If owned policy requires reconciliation, fail closed and
// let the normal observation loop perform the authoritative update.
func (s *Store) currentDesired(ctx context.Context, certificate string) (Desired, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Desired{}, err
	}
	node, ok := s.nodes[certificate]
	if !ok || s.entryRetiredLocked(node.ID) || node.TransportTail != nil {
		return Desired{}, errors.New("control: node state unavailable")
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return Desired{}, errors.New("control: owned business unavailable")
	}
	projected, _, err := projectBusinessEntries(s.nodes, s.business.material, time.Now())
	if err != nil || !reflect.DeepEqual(projected[certificate].Desired, node.Desired) {
		return Desired{}, errors.New("control: policy requires reconciliation")
	}
	return node.Desired.clone(), nil
}

func (s *Store) Exchange(ctx context.Context, certificate string, receipt *Observation) (Desired, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Desired{}, err
	}
	node, ok := s.nodes[certificate]
	if !ok || s.entryRetiredLocked(node.ID) {
		return Desired{}, errors.New("control: not enrolled")
	}
	if node.TransportTail != nil {
		return Desired{}, errors.New("control: private transport maintenance requires explicit completion")
	}
	if err := s.observeBusinessTrafficLocked(node, receipt, time.Now().UTC()); err != nil {
		return Desired{}, err
	}
	if err := s.reconcileOwnedEntriesLocked(time.Now()); err != nil {
		return Desired{}, err
	}
	node = s.nodes[certificate]
	now := time.Now().UTC()
	old := node
	if node.EntryQuota != nil {
		if s.business != nil {
			return Desired{}, errors.New("control: staged quota and owned ledger cannot both write")
		}
		quota, desired, err := advanceEntryQuota(node.EntryQuota, node.Desired, receipt, now)
		if err != nil {
			return Desired{}, err
		}
		node.EntryQuota, node.Desired = quota, desired
	}
	if reflect.DeepEqual(node.EntryQuota, old.EntryQuota) && node.Desired.Entry != nil && receipt != nil && receipt.EntryHealth != nil && glivela.VerifyAppliedReceipt(node.Desired.DesiredArtifact, receipt.AppliedReceipt) == nil && !receipt.EntryHealth.SampledAt.IsZero() && !receipt.EntryHealth.SampledAt.After(now) && !receipt.EntryHealth.SampledAt.After(node.EntryHealthBarrierAt) {
		// Delayed/replayed old success must not overwrite a newer blocked
		// observation or extend freshness. It still receives current policy.
		return node.Desired.clone(), nil
	}
	// Every authenticated observation supersedes the previous health report.
	// A missing/stale report can occur after failed recovery or lost local state;
	// keeping the old successful receipt would incorrectly show a healthy node.
	node.Receipt = nil
	if receipt != nil {
		copyReceipt := receipt.clone()
		if glivela.VerifyAppliedReceipt(node.Desired.DesiredArtifact, copyReceipt.AppliedReceipt) == nil {
			// Bad/incomplete peer data supersedes the previous proof but must
			// not stop an enrolled node receiving its current desired policy.
			if validateEntryHealth(node.Desired, copyReceipt.EntryHealth) != nil || copyReceipt.EntryHealth != nil && copyReceipt.EntryHealth.SampledAt.After(now) {
				copyReceipt.EntryHealth = nil
			}
			if validateEntryTraffic(node.Desired, copyReceipt.Traffic) != nil || copyReceipt.Traffic != nil && copyReceipt.Traffic.SampledAt.After(now) {
				copyReceipt.Traffic = nil
			}
			node.Receipt = &copyReceipt
		}
	}
	if node.Desired.Entry != nil {
		if node.Receipt != nil && node.Receipt.EntryHealth != nil {
			node.EntryHealthBarrierAt = node.Receipt.EntryHealth.SampledAt
		} else {
			node.EntryHealthBarrierAt = now
		}
	}
	node.ReportedAt = now
	node.PublicationSuspended = s.suspended(node.ID, now) || !s.availableRuntime(node, now)
	next := s.copy()
	next[certificate] = node
	if node.Desired.Entry != nil {
		if err := invalidateChangedEntryProofs(next, old, node, now); err != nil {
			return Desired{}, err
		}
	}
	if err := reconcileOwnedRouteChecks(next, s.business, now, s.effectiveAvailabilities()); err != nil {
		return Desired{}, err
	}
	if err := s.commit(next); err != nil {
		return Desired{}, err
	}
	// A stale report is not accepted as healthy, but must not prevent the node
	// from receiving a newer desired revision after an interrupted update.
	result := node.Desired.clone()
	return result, nil
}

func (s *Store) copy() map[string]Node {
	result := make(map[string]Node, len(s.nodes))
	for key, node := range s.nodes {
		result[key] = node
	}
	return result
}

func (s *Store) commit(nodes map[string]Node) error {
	if err := s.retainQuotaSuspensions(nodes); err != nil {
		return err
	}
	nodes = maps.Clone(nodes)
	values := make([]Node, 0, len(nodes))
	for key, node := range nodes {
		if record, affected := s.availability.Nodes[node.ID]; affected {
			node.AvailabilityRevision = max(node.AvailabilityRevision, record.Revision)
		}
		for id := range node.RouteEntries {
			if record, affected := s.availability.Nodes[id]; affected {
				node.AvailabilityRevision = max(node.AvailabilityRevision, record.Revision)
			}
		}
		nodes[key] = node
		values = append(values, node)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	raw, err := json.Marshal(values)
	if err != nil || len(raw) > maxMessage {
		return errors.New("control: state limit exceeded")
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), ".glivela-state-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), s.path); err != nil {
		return err
	}
	// Notify only new commands or revisions; ordinary receipts do not trigger an observation loop.
	for cert, current := range nodes {
		previous, existed := s.nodes[cert]
		if !existed || previous.Desired.Revision != current.Desired.Revision || previous.Desired.ConfigSHA256 != current.Desired.ConfigSHA256 {
			s.nodeEvents.wake(cert, nodeSignalDesired)
		}
		if current.Network != nil && current.Network.Command != nil && current.Network.Result == nil && (!existed || previous.Network == nil || previous.Network.Command == nil || previous.Network.Command.ID != current.Network.Command.ID) {
			s.nodeEvents.wake(cert, nodeSignalNetwork)
		}
		for entry, check := range current.Checks {
			old, ok := previous.Checks[entry]
			if check.Result == nil && (!existed || !ok || old.Request.AttemptID != check.Request.AttemptID) {
				s.nodeEvents.wake(check.CertificateID, nodeSignalRoute)
			}
		}
	}
	s.nodes = nodes
	if s.speedHub != nil {
		s.speedHub.wake()
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	return nil
}
