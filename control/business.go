package control

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
)

// businessState is loaded only by the controller while it holds the directory
// lease. The staged checkpoint is recovery evidence; business.json becomes
// the sole current business source after offline ownership commit. Loading
// either does not establish runtime or end-to-end route health.
type businessState struct {
	snapshotID string
	material   glivela.ImportMaterial
	keyPath    string
	faulted    bool
}

type BusinessAccount struct {
	Account  glivela.Account                          `json:"account"`
	Schedule glivela.ImportResetSchedule              `json:"schedule"`
	Usage    []glivela.UsageMember                    `json:"usage"`
	Traffic  map[string]glivela.ImportTrafficCounters `json:"traffic"`
}

// Browser clients must not round original 64-bit ledger values through a
// JavaScript Number. The API uses decimal strings for these fields; the owned
// state remains typed int64/uint64 and is never rewritten for presentation.
func (a BusinessAccount) MarshalJSON() ([]byte, error) {
	type plan struct {
		glivela.AccountPlan
		TotalBytes int64 `json:"totalBytes,string"`
		ExpiryTime int64 `json:"expiryTime,string"`
	}
	type account struct {
		glivela.Account
		Plan            plan   `json:"plan"`
		DesiredRevision uint64 `json:"desiredRevision,string"`
		AppliedRevision uint64 `json:"appliedRevision,string"`
	}
	type usage struct {
		glivela.UsageMember
		Baseline int64 `json:"baseline,string"`
		Observed int64 `json:"observed,string"`
	}
	type traffic struct {
		glivela.ImportTrafficCounters
		UploadBytes      int64 `json:"uploadBytes,string"`
		DownloadBytes    int64 `json:"downloadBytes,string"`
		RawUploadBytes   int64 `json:"rawUploadBytes,string"`
		RawDownloadBytes int64 `json:"rawDownloadBytes,string"`
	}
	view := struct {
		Account  account                     `json:"account"`
		Schedule glivela.ImportResetSchedule `json:"schedule"`
		Usage    []usage                     `json:"usage"`
		Traffic  map[string]traffic          `json:"traffic"`
	}{Account: account{a.Account, plan{a.Account.Plan, a.Account.Plan.TotalBytes, a.Account.Plan.ExpiryTime}, a.Account.DesiredRevision, a.Account.AppliedRevision}, Schedule: a.Schedule, Usage: []usage{}, Traffic: map[string]traffic{}}
	for _, member := range a.Usage {
		view.Usage = append(view.Usage, usage{member, member.Baseline, member.Observed})
	}
	for id, c := range a.Traffic {
		view.Traffic[id] = traffic{c, c.UploadBytes, c.DownloadBytes, c.RawUploadBytes, c.RawDownloadBytes}
	}
	return json.Marshal(view)
}

// BusinessInventory deliberately has no credential, subscription-token,
// endpoint-private-key, certificate-private-key or retained-source fields.
// Historical statuses are not current runtime-health evidence.
type BusinessInventory struct {
	State      string             `json:"state"`
	SnapshotID string             `json:"snapshotId,omitempty"`
	Accounts   []BusinessAccount  `json:"accounts"`
	Nodes      []BusinessNode     `json:"nodes"`
	Endpoints  []BusinessEndpoint `json:"endpoints"`
}

type BusinessNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type BusinessEndpoint struct {
	ID         string `json:"id"`
	EntryID    string `json:"entryId"`
	NodeID     string `json:"nodeId"`
	ServiceID  string `json:"serviceId"`
	Name       string `json:"name"`
	RegionCode string `json:"regionCode"`
}

// LoadBusiness must run before serving requests and under the same directory
// lease as OpenStore. A present checkpoint without its independent storage key
// is a startup error, never a reason to initialize an empty business database.
// Bootstrap supplies a key FILE, not any business data or raw inline secrets.
func (s *Store) LoadBusiness(keyPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.business != nil {
		return errors.New("control: business state already loaded")
	}
	directory := filepath.Dir(s.path)
	owned, err := businessAdoptionStarted(directory)
	if err != nil {
		return err
	}
	if keyPath == "" {
		if owned {
			return errors.New("control: owned business requires its storage key")
		}
		_, err := os.Lstat(filepath.Join(directory, "business.pending.json"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("control: business checkpoint requires its storage key")
	}
	key, err := readBusinessKey(keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	read := readStagedImport
	if owned {
		read = readOwnedBusiness
	}
	material, snapshot, err := read(directory, key)
	if err != nil {
		return errors.New("control: business checkpoint unavailable or invalid")
	}
	if material.Ownership != nil {
		projected, changed, err := projectBusinessEntries(s.nodes, material, time.Now())
		if err != nil {
			return err
		}
		if changed {
			if err := s.commit(projected); err != nil {
				return err
			}
		}
	}
	s.business = &businessState{snapshotID: snapshot, material: material, keyPath: keyPath}
	return nil
}

func readBusinessKey(path string) ([]byte, error) {
	invalid := errors.New("control: private 256-bit business storage key file required")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, invalid
	}
	for parent := filepath.Dir(path); parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, invalid
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		return nil, invalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, invalid
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 {
		return nil, invalid
	}
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, invalid
	}
	return key, nil
}

// Business returns a detached, secret-free view. No caller receives a pointer
// into live account plans, ledger watermarks or the immutable source archive.
func (s *Store) Business() BusinessInventory {
	s.mu.Lock()
	defer s.mu.Unlock()
	view := BusinessInventory{State: "empty", Accounts: []BusinessAccount{}, Nodes: []BusinessNode{}, Endpoints: []BusinessEndpoint{}}
	if s.business == nil {
		return view
	}
	m := s.business.material
	view.State, view.SnapshotID = "awaiting-handover", s.business.snapshotID
	if m.Ownership != nil {
		view.State = "owned-unverified"
	}
	if s.business.faulted {
		view.State = "storage-unverified"
	}
	for id, node := range m.References.Nodes {
		view.Nodes = append(view.Nodes, BusinessNode{ID: id, Name: node.Name})
	}
	slices.SortFunc(view.Nodes, func(a, b BusinessNode) int { return strings.Compare(a.ID, b.ID) })
	for _, endpoint := range m.Endpoints {
		service := m.References.Services[endpoint.ServiceID]
		app := m.References.Applications[service.ApplicationID]
		view.Endpoints = append(view.Endpoints, BusinessEndpoint{ID: endpoint.Reality.ID, EntryID: endpoint.Reality.EntryID, NodeID: app.NodeID, ServiceID: endpoint.ServiceID, Name: app.Name, RegionCode: service.RegionCode})
	}
	slices.SortFunc(view.Endpoints, func(a, b BusinessEndpoint) int { return strings.Compare(a.ID, b.ID) })
	for _, item := range m.Plan.Accounts {
		account := BusinessAccount{Account: item.Account, Schedule: m.ResetSchedules[item.Account.ID], Usage: append([]glivela.UsageMember{}, item.Usage...), Traffic: map[string]glivela.ImportTrafficCounters{}}
		for _, credential := range item.Credentials {
			account.Traffic[credential.ID] = m.TrafficCounters[credential.ID]
		}
		view.Accounts = append(view.Accounts, account)
	}
	return view
}
