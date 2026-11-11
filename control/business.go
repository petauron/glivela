package control

import (
	"crypto/sha256"
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
	fileSHA256 [32]byte
	keySHA256  [32]byte
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
	ClientChains []ClientChainView  `json:"clientChains"`
	Availability availabilityState  `json:"availability"`
	State        string             `json:"state"`
	SnapshotID   string             `json:"snapshotId,omitempty"`
	Accounts     []BusinessAccount  `json:"accounts"`
	Nodes        []BusinessNode     `json:"nodes"`
	Endpoints    []BusinessEndpoint `json:"endpoints"`
	Routes       []BusinessRoute    `json:"routes"`
	Runtimes     []BusinessRuntime  `json:"runtimes"`
}

type BusinessRoute struct {
	Port         int    `json:"port"`
	IPv4Port     int    `json:"ipv4Port,omitempty"`
	ID           string `json:"id"`
	AccountID    string `json:"accountId"`
	EntryID      string `json:"entryId"`
	EgressID     string `json:"egressId"`
	IPv4EgressID string `json:"ipv4EgressId,omitempty"`
	Enabled      bool   `json:"enabled"`
	HideNative   bool   `json:"hideNative"`
	State        string `json:"state"`
}

type BusinessRuntime struct {
	HostID       string    `json:"hostId,omitempty"`
	ID           string    `json:"id"`
	Role         string    `json:"role"`
	Revision     uint64    `json:"revision,string"`
	RuntimeReady bool      `json:"runtimeReady"`
	ReportedAt   time.Time `json:"reportedAt"`
	Peers        []string  `json:"peers"`
}

type BusinessNode struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	CenterAgentID string `json:"centerAgentId,omitempty"`
}

type BusinessEndpoint struct {
	NextResetAt string `json:"nextResetAt,omitempty"`
	ID          string `json:"id"`
	EntryID     string `json:"entryId"`
	NodeID      string `json:"nodeId"`
	ServiceID   string `json:"serviceId"`
	Name        string `json:"name"`
	RegionCode  string `json:"regionCode"`
	Retired     bool   `json:"retired"`
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
	for _, node := range s.nodes {
		if node.EntryQuota != nil && keyPath != "" {
			return errors.New("control: staged quota cannot load a second business owner")
		}
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
	var material glivela.ImportMaterial
	var snapshot string
	var fileSHA [32]byte
	if owned {
		material, snapshot, fileSHA, err = readOwnedBusinessVersion(directory, key)
	} else {
		material, snapshot, err = readStagedImport(directory, key)
	}
	if err != nil {
		return errors.New("control: business checkpoint unavailable or invalid")
	}
	presentation, err := loadSubscriptionPresentation(directory, material)
	if err != nil {
		return err
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
	s.subscriptionNames = presentation.Names
	s.subscriptionLandings = presentation.Landings
	s.business = &businessState{snapshotID: snapshot, material: material, keyPath: keyPath, fileSHA256: fileSHA, keySHA256: sha256.Sum256(key)}
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
	view := BusinessInventory{State: "empty", Availability: availabilityState{Version: s.availability.Version, Revision: s.availability.Revision, Nodes: s.effectiveAvailabilities()}, Accounts: []BusinessAccount{}, Nodes: []BusinessNode{}, Endpoints: []BusinessEndpoint{}, Routes: []BusinessRoute{}, Runtimes: []BusinessRuntime{}}
	view.ClientChains = []ClientChainView{}
	if s.business != nil {
		for _, c := range s.business.material.ClientChains {
			if s.business.material.DeletedClientChains[c.ID] || s.entryRetiredLocked(c.EntryID) {
				continue
			}
			c, err := s.business.material.EffectiveClientChain(c)
			if err != nil {
				continue
			}
			item := ClientChainView{EgressIP: c.EgressIP, UnavailableReason: clientChainUnavailableReason(s.nodes, c), Shared: c.Shared, Port: c.Port, ID: c.ID, AccountID: c.AccountID, EntryID: c.EntryID, EgressID: c.EgressID, Name: c.Name, Enabled: c.Enabled, Transport: c.Transport, SourceIPv6: c.SourceIPv6, ServerIPv6: c.ServerIPv6}
			if c.Relay != nil {
				item.RelayID, item.RelaySourceIPv6, item.RelayServerIPv6 = c.Relay.NodeID, c.Relay.SourceIPv6, c.Relay.ServerIPv6
				item.RelayTransport, item.RelaySourceIPv4, item.RelayServerIPv4 = c.Relay.Transport, c.Relay.SourceIPv4, c.Relay.ServerIPv4
			}
			view.ClientChains = append(view.ClientChains, item)
		}
	}
	if s.business == nil {
		// Transport-only staged controllers still own enrollment and availability;
		// they must not need to adopt the legacy ledger to pause a known source.
		names := map[string]bool{}
		for _, node := range s.nodes {
			role := "landing"
			peers := []string{}
			if node.Desired.Entry != nil {
				role = "entry"
				for _, peer := range node.Desired.EntryNetwork.Peers {
					peers = append(peers, peer.EgressID)
				}
			}
			names[node.ID] = true
			for id := range node.RouteEntries {
				names[id] = true
			}
			view.Runtimes = append(view.Runtimes, BusinessRuntime{ID: node.ID, Role: role, Revision: node.Desired.Revision, RuntimeReady: s.availableRuntime(node, time.Now()), ReportedAt: node.ReportedAt, Peers: peers})
			if node.EntryQuota != nil {
				view.Endpoints = append(view.Endpoints, BusinessEndpoint{ID: node.ID, EntryID: node.ID, Name: node.ID, NextResetAt: node.EntryQuota.NextResetAt.Format(time.RFC3339)})
			}
		}
		for id := range names {
			view.Nodes = append(view.Nodes, BusinessNode{ID: id, Name: id})
		}
		slices.SortFunc(view.Nodes, func(a, b BusinessNode) int { return strings.Compare(a.ID, b.ID) })
		slices.SortFunc(view.Runtimes, func(a, b BusinessRuntime) int { return strings.Compare(a.ID, b.ID) })
		return view
	}
	m := s.business.material
	view.State, view.SnapshotID = "awaiting-handover", s.business.snapshotID
	if m.Ownership != nil {
		// Ownership is independent of node and route acceptance below.
		view.State = "owned"
	}
	if s.business.faulted {
		view.State = "storage-unverified"
	}
	for id, node := range m.References.Nodes {
		view.Nodes = append(view.Nodes, BusinessNode{ID: id, Name: node.Name, CenterAgentID: s.hostBindings[id]})
	}
	slices.SortFunc(view.Nodes, func(a, b BusinessNode) int { return strings.Compare(a.ID, b.ID) })
	for _, endpoint := range m.Endpoints {
		service := m.References.Services[endpoint.ServiceID]
		app := m.References.Applications[service.ApplicationID]
		view.Endpoints = append(view.Endpoints, BusinessEndpoint{NextResetAt: endpoint.ResetSchedule.NextResetAt, ID: endpoint.Reality.ID, EntryID: endpoint.Reality.EntryID, NodeID: app.NodeID, ServiceID: endpoint.ServiceID, Name: app.Name, RegionCode: service.RegionCode, Retired: endpoint.Retired})
	}
	slices.SortFunc(view.Endpoints, func(a, b BusinessEndpoint) int { return strings.Compare(a.ID, b.ID) })
	now := time.Now().UTC()
	credentials, grants, projectionErr := effectiveBusinessCredentials(m, now)
	for _, item := range m.Plan.Accounts {
		account := BusinessAccount{Account: item.Account, Schedule: m.ResetSchedules[item.Account.ID], Usage: append([]glivela.UsageMember{}, item.Usage...), Traffic: map[string]glivela.ImportTrafficCounters{}}
		for _, credential := range item.Credentials {
			account.Traffic[credential.ID] = m.TrafficCounters[credential.ID]
		}
		view.Accounts = append(view.Accounts, account)
		for _, grant := range item.Grants {
			if m.DeletedRoutes[grant.ID] || entryRetired(m, grant.EntryID) {
				continue
			}
			state := "unverified"
			if !grant.Enabled {
				state = "disabled"
			} else if m.Ownership != nil && !s.business.faulted {
				effective := grants[grant.ID]
				if projectionErr == nil && !effective.Deployable() {
					state = "policy-disabled"
				}
				for _, entry := range s.nodes {
					if projectionErr != nil || entry.ID != grant.EntryID || entry.Desired.Entry == nil || !effective.Deployable() || !s.availableRuntime(entry, now) {
						continue
					}
					if slices.Contains(entry.Desired.Entry.Credentials, credentials[grant.Base.ID]) && slices.Contains(entry.Desired.Entry.Credentials, credentials[grant.Route.ID]) && slices.ContainsFunc(entry.Desired.Entry.Grants, func(current glivela.RouteGrant) bool { return sameGrantPolicy(current, effective) }) && s.subscriptionPeerReady(entry, grant.EgressID, now) && (grant.IPv4EgressID == "" || s.subscriptionPeerReady(entry, grant.IPv4EgressID, now)) {
						state = "verified"
					}
				}
			}
			if s.suspended(grant.EntryID, now) || s.suspended(grant.EgressID, now) || s.suspended(grant.IPv4EgressID, now) {
				state = "temporarily-suspended"
			}
			port, ipv4Port := 0, 0
			for _, entry := range s.nodes {
				if entry.ID != grant.EntryID || entry.Desired.Entry == nil {
					continue
				}
				for _, peer := range entry.Desired.Entry.Peers {
					if peer.EgressID == grant.EgressID {
						port = peer.Port
					}
					if peer.EgressID == grant.IPv4EgressID {
						ipv4Port = peer.Port
					}
				}
			}
			view.Routes = append(view.Routes, BusinessRoute{Port: port, IPv4Port: ipv4Port, ID: grant.ID, AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: grant.EgressID, IPv4EgressID: grant.IPv4EgressID, Enabled: grant.Enabled, HideNative: grant.HideNative, State: state})
		}
	}
	for _, node := range s.nodes {
		if entryRetired(m, node.ID) {
			continue
		}
		hostID := runtimeHostID(m, node)
		if _, referenced := m.References.Nodes[node.ID]; hostID == "" && !referenced {
			// A freshly enrolled runtime may not yet be referenced by the
			// imported business inventory. Keep its own stable runtime ID as
			// a display-only association target; never add it to the ledger.
			view.Nodes = append(view.Nodes, BusinessNode{ID: node.ID, Name: node.ID, CenterAgentID: s.hostBindings[node.ID]})
		}
		role := "landing"
		peers := []string{}
		if node.Desired.Entry != nil {
			role = "entry"
			for _, peer := range node.Desired.EntryNetwork.Peers {
				peers = append(peers, peer.EgressID)
			}
		}
		slices.Sort(peers)
		view.Runtimes = append(view.Runtimes, BusinessRuntime{HostID: hostID, ID: node.ID, Role: role, Revision: node.Desired.Revision, RuntimeReady: s.availableRuntime(node, time.Now()), ReportedAt: node.ReportedAt, Peers: peers})
	}
	slices.SortFunc(view.Nodes, func(a, b BusinessNode) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(view.Runtimes, func(a, b BusinessRuntime) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(view.Routes, func(a, b BusinessRoute) int { return strings.Compare(a.ID, b.ID) })
	return view
}
