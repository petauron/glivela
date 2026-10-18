package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	glivela "github.com/petauron/glivela"
)

type Node struct {
	ID            string                  `json:"id"`
	CertificateID string                  `json:"certificateId"`
	Desired       Desired                 `json:"desired"`
	Receipt       *glivela.AppliedReceipt `json:"receipt,omitempty"`
	ReportedAt    time.Time               `json:"reportedAt,omitempty"`
}

// Store is a bounded single-process state file for the MVP. Callers must run
// one controller per directory; it is not a multi-writer database protocol.
// No private keys are stored here. Configuration files remain private (0600).
type Store struct {
	mu    sync.Mutex
	path  string
	nodes map[string]Node
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
		if node.ID == "" || !glivela.ValidIdentity(node.CertificateID) || node.Desired.Validate() != nil || seen[node.ID] {
			return nil, errors.New("control: invalid node")
		}
		if _, ok := s.nodes[node.CertificateID]; ok {
			return nil, errors.New("control: duplicate enrollment")
		}
		if node.Receipt != nil && glivela.VerifyAppliedReceipt(node.Desired.DesiredArtifact, *node.Receipt) != nil {
			return nil, errors.New("control: invalid stored receipt")
		}
		seen[node.ID] = true
		s.nodes[node.CertificateID] = node
	}
	return s, nil
}

// Put is a local controller operation, never exposed on the node HTTP API.
// Stable node identity survives configuration changes. Certificate rotation
// requires the same node ID and atomically revokes the previous certificate.
func (s *Store) Put(node Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if node.ID == "" || !glivela.ValidIdentity(node.CertificateID) || node.Desired.Validate() != nil {
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
		if node.Desired.Revision < old.Desired.Revision || node.Desired.Revision == old.Desired.Revision && node.Desired.ConfigSHA256 != old.Desired.ConfigSHA256 {
			return errors.New("control: non-monotonic desired state")
		}
		delete(next, key)
	}
	// Administrative imports cannot manufacture a ready node.
	node.Receipt = nil
	node.ReportedAt = time.Time{}
	node.Desired = node.Desired.clone()
	next[node.CertificateID] = node
	return s.commit(next)
}

func (s *Store) Exchange(ctx context.Context, certificate string, receipt *glivela.AppliedReceipt) (Desired, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Desired{}, err
	}
	node, ok := s.nodes[certificate]
	if !ok {
		return Desired{}, errors.New("control: not enrolled")
	}
	if receipt != nil && receipt.Revision == node.Desired.Revision && receipt.ConfigSHA256 == node.Desired.ConfigSHA256 {
		copyReceipt := *receipt
		node.Receipt = nil
		if glivela.VerifyAppliedReceipt(node.Desired.DesiredArtifact, copyReceipt) == nil {
			node.Receipt = &copyReceipt
		}
		node.ReportedAt = time.Now().UTC()
		next := s.copy()
		next[certificate] = node
		if err := s.commit(next); err != nil {
			return Desired{}, err
		}
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
