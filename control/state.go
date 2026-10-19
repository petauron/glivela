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
	mu           sync.Mutex
	path         string
	nodes        map[string]Node
	business     *businessState
	managementUI http.Handler
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
	s := &Store{path: path, nodes: map[string]Node{}}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
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
		if !glivela.ValidIdentifier(node.ID) || !glivela.ValidIdentity(node.CertificateID) || node.Desired.Validate() != nil || seen[node.ID] || validateNodeRole(node) != nil {
			return nil, errors.New("control: invalid node")
		}
		if _, ok := s.nodes[node.CertificateID]; ok {
			return nil, errors.New("control: duplicate enrollment")
		}
		if node.Receipt != nil && glivela.VerifyAppliedReceipt(node.Desired.DesiredArtifact, node.Receipt.AppliedReceipt) != nil {
			return nil, errors.New("control: invalid stored receipt")
		}
		if node.Receipt != nil && validateEntryHealth(node.Desired, node.Receipt.EntryHealth) != nil {
			return nil, errors.New("control: invalid stored entry observation")
		}
		for entry, check := range node.Checks {
			if entry != check.Request.EntryID || !routeTargetsLanding(check.Request, node) || check.Request.Validate() != nil || !glivela.ValidIdentity(check.CertificateID) || check.IssuedAt.IsZero() || check.Result != nil && validateRouteResult(check.Request, *check.Result) != nil {
				return nil, errors.New("control: invalid stored route check")
			}
			if len(node.Checks) > 64 || check.Request.Revision != node.Desired.Revision || check.Request.ConfigSHA256 != node.Desired.ConfigSHA256 || (check.Result == nil) != check.ReceivedAt.IsZero() {
				return nil, errors.New("control: inconsistent stored route check")
			}
		}
		if len(node.Checks) > 0 && !completeRouteInventory(node, node.Checks) {
			return nil, errors.New("control: incomplete stored entry verification inventory")
		}
		seen[node.ID] = true
		s.nodes[node.CertificateID] = node
	}
	if err := validateEnrollmentRoles(s.nodes); err != nil {
		return nil, err
	}
	return s, nil
}

// Put is a local controller operation, never exposed on the node HTTP API.
// Stable node identity survives configuration changes. Certificate rotation
// requires the same node ID and atomically revokes the previous certificate.
func (s *Store) Put(node Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !glivela.ValidIdentifier(node.ID) || !glivela.ValidIdentity(node.CertificateID) || node.Desired.Validate() != nil || len(node.Checks) != 0 || validateNodeRole(node) != nil {
		return errors.New("control: invalid enrollment")
	}
	next := s.copy()
	if existing, ok := next[node.CertificateID]; ok && existing.ID != node.ID {
		return errors.New("control: certificate already assigned")
	}
	for key, old := range next {
		if old.ID != node.ID {
			continue
		}
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
	return s.commit(next)
}

func (s *Store) Exchange(ctx context.Context, certificate string, receipt *Observation) (Desired, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Desired{}, err
	}
	node, ok := s.nodes[certificate]
	if !ok {
		return Desired{}, errors.New("control: not enrolled")
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
	if node.Desired.Entry != nil && receipt != nil && receipt.EntryHealth != nil && glivela.VerifyAppliedReceipt(node.Desired.DesiredArtifact, receipt.AppliedReceipt) == nil && !receipt.EntryHealth.SampledAt.IsZero() && !receipt.EntryHealth.SampledAt.After(now) && !receipt.EntryHealth.SampledAt.After(node.EntryHealthBarrierAt) {
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
	next := s.copy()
	next[certificate] = node
	if node.Desired.Entry != nil {
		if err := invalidateChangedEntryProofs(next, old, node, now); err != nil {
			return Desired{}, err
		}
	}
	if err := reconcileOwnedRouteChecks(next, s.business, now); err != nil {
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
	values := make([]Node, 0, len(nodes))
	for _, node := range nodes {
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
	s.nodes = nodes
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
