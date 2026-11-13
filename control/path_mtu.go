package control

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"time"

	glivela "github.com/petauron/glivela"
)

// A setting belongs to an entry and a destination, never to an account or port.
// Its address is derived from enrolled policy, not accepted from the browser.
type PathMTUCommand struct {
	Address  string `json:"address"`
	MTU      int    `json:"mtu"`
	Revision uint64 `json:"revision,string"`
	Hash     string `json:"hash"`
}

type PathMTUObservation struct {
	Address      string    `json:"address"`
	CheckedAt    time.Time `json:"checkedAt"`
	Configured   int       `json:"configured"`
	Actual       int       `json:"actual"`
	Interface    string    `json:"interface"`
	InterfaceMTU int       `json:"interfaceMtu"`
	Fingerprint  string    `json:"fingerprint"`
	CanChange    bool      `json:"canChange"`
	CanRestore   bool      `json:"canRestore"`
	Reason       string    `json:"reason,omitempty"`
}

type pathMTUView struct {
	Address   string              `json:"address"`
	Revision  uint64              `json:"revision,string"`
	Shared    int                 `json:"shared"`
	Supported bool                `json:"supported"`
	Online    bool                `json:"online"`
	Pending   bool                `json:"pending"`
	Snapshot  *PathMTUObservation `json:"snapshot,omitempty"`
	Result    *NetworkResult      `json:"result,omitempty"`
}

func pathMTUAddress(address string) bool {
	a, err := netip.ParseAddr(address)
	return err == nil && a.String() == address && (glivela.PublicTransportIPv4(address) || glivela.PublicTransportIPv6(address))
}

func pathMTUMin(address string) int {
	if a, err := netip.ParseAddr(address); err == nil && a.Is6() {
		return 1280
	}
	return 576
}

func pathMTUAllowed(d Desired, address string) bool {
	if d.Entry == nil || d.EntryNetwork == nil || !pathMTUAddress(address) {
		return false
	}
	for _, peer := range d.Entry.Peers {
		if peer.DialTransport().Endpoint(peer.Address) == address {
			return true
		}
	}
	for _, peer := range d.EntryNetwork.SpeedPeers {
		if peer.Address == address {
			return true
		}
	}
	return false
}

// Reuse the exact authenticated transport binding used by proxy configuration.
func (s *Store) pathMTUTargetLocked(mode, id, landingID string) (Node, string, error) {
	fail := errors.New("线路未启用或目标尚未授权")
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return Node{}, "", fail
	}
	m := s.business.material
	if mode == "client" {
		credentials, _, err := effectiveBusinessCredentials(m, time.Now())
		if err != nil {
			return Node{}, "", fail
		}
		for _, c := range m.ClientChains {
			if c.ID != id || c.EgressID != landingID {
				continue
			}
			peer, entry, _, ok := chainSpeedPeer(s.nodes, m, c, credentials)
			if ok && pathMTUAllowed(entry.Desired, peer.Address) {
				return entry, peer.Address, nil
			}
		}
	} else if mode == "server" {
		for _, a := range m.Plan.Accounts {
			if !a.Account.Plan.Enabled {
				continue
			}
			for _, g := range a.Grants {
				if g.ClientChainID != "" || g.ID != id || !g.Enabled || g.EgressID != landingID && g.IPv4EgressID != landingID {
					continue
				}
				t, ok := s.serverLatencyTargetLocked(g.EntryID, landingID)
				entry := s.nodes[t.Certificate]
				if ok && pathMTUAllowed(entry.Desired, t.Address) {
					return entry, t.Address, nil
				}
			}
		}
	}
	return Node{}, "", fail
}

func (s *Store) managePathMTU(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Mode             string `json:"mode"`
		RouteID          string `json:"routeId"`
		LandingID        string `json:"landingId"`
		Action           string `json:"action"`
		MTU              int    `json:"mtu"`
		ExpectedRevision uint64 `json:"expectedRevision,string"`
		Expected         string `json:"expected"`
	}
	if decode(http.MaxBytesReader(w, r.Body, 4096), &input) != nil {
		http.Error(w, "invalid path MTU request", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, address, err := s.pathMTUTargetLocked(input.Mode, input.RouteID, input.LandingID)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	settings := NetworkSettings{}
	if n.Network != nil {
		settings = *n.Network
	}
	now := time.Now().UTC()
	view := pathMTUView{Address: address, Revision: settings.Revision, Online: s.availableRuntime(n, now), Supported: now.Sub(s.pathMTUNodes[n.CertificateID]) < 2*time.Minute}
	// Count displayed routes sharing this destination, across accounts/modes.
	for _, c := range s.business.material.ClientChains {
		if entry, addr, e := s.pathMTUTargetLocked("client", c.ID, c.EgressID); e == nil && entry.ID == n.ID && addr == address {
			view.Shared++
		}
	}
	for _, a := range s.business.material.Plan.Accounts {
		for _, g := range a.Grants {
			for _, landing := range []string{g.EgressID, g.IPv4EgressID} {
				if landing == "" {
					continue
				}
				if entry, addr, e := s.pathMTUTargetLocked("server", g.ID, landing); e == nil && entry.ID == n.ID && addr == address {
					view.Shared++
				}
			}
		}
	}
	if snap, ok := settings.Paths[address]; ok {
		view.Snapshot = &snap
	}
	if snap, ok := s.pathMTUReports[n.CertificateID][address]; ok {
		view.Snapshot = &snap
	}
	if c := settings.Command; c != nil {
		view.Pending = settings.Result == nil && now.Before(c.ExpiresAt)
		if c.PathMTU != nil && c.PathMTU.Address == address {
			view.Result = settings.Result
		}
	}
	if input.Action != "get" {
		fail := func(message string) { http.Error(w, message, 409) }
		if input.Action != "inspect" && input.Action != "set" && input.Action != "auto" {
			http.Error(w, "invalid path MTU action", 400)
			return
		}
		if !view.Supported || !view.Online || s.suspended(n.ID, now) {
			fail("节点离线、未就绪或需升级后才能设置路径 MTU")
			return
		}
		if settings.Revision != input.ExpectedRevision || settings.Revision == ^uint64(0) {
			fail("设置已变化，请刷新")
			return
		}
		if view.Pending {
			fail("已有网络操作正在处理")
			return
		}
		if input.Action != "inspect" {
			v := view.Snapshot
			if v == nil || (!v.CanChange && (input.Action != "auto" || !v.CanRestore)) || now.Sub(v.CheckedAt) > 2*time.Minute || v.Fingerprint != input.Expected {
				fail("请先重新检测当前路径")
				return
			}
			if input.Action == "set" && (input.MTU < pathMTUMin(address) || input.MTU > v.InterfaceMTU) {
				fail("MTU 超出此地址族或网卡允许范围")
				return
			}
		}
		if len(settings.Paths) >= 32 && settings.Paths[address].Address == "" {
			fail("路径设置数量已达上限")
			return
		}
		id, e := newRouteAttempt()
		if e != nil {
			fail("无法创建操作")
			return
		}
		mtu := input.MTU
		if input.Action == "auto" {
			mtu = 0
		}
		settings.Command = &NetworkCommand{ID: id, Action: "path-" + input.Action, Expected: input.Expected, ExpiresAt: now.Add(2 * time.Minute), Actor: CertificateID(r.TLS.PeerCertificates[0]), PathMTU: &PathMTUCommand{Address: address, MTU: mtu, Revision: n.Desired.Revision, Hash: n.Desired.ConfigSHA256}}
		settings.Result = nil
		settings.Revision++
		n.Network = &settings
		next := s.copy()
		next[n.CertificateID] = n
		if s.commit(next) != nil {
			fail("设置未保存")
			return
		}
		view.Revision = settings.Revision
		view.Pending = true
		view.Result = nil
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

func (s *Store) acceptPathMTUReport(cert string, n Node, report *NetworkReport) error {
	if report.PathMTUSupported {
		if s.pathMTUNodes == nil {
			s.pathMTUNodes = map[string]time.Time{}
		}
		s.pathMTUNodes[cert] = time.Now()
	}
	if len(report.Paths) > 32 {
		return errors.New("too many path observations")
	}
	if s.pathMTUReports == nil {
		s.pathMTUReports = map[string]map[string]PathMTUObservation{}
	}
	if s.pathMTUReports[cert] == nil {
		s.pathMTUReports[cert] = map[string]PathMTUObservation{}
	}
	for _, v := range report.Paths {
		commandMatches := n.Network != nil && n.Network.Command != nil && n.Network.Command.PathMTU != nil && report.Result != nil && n.Network.Command.ID == report.Result.ID && n.Network.Command.PathMTU.Address == v.Address
		if !commandMatches && (n.Network == nil || n.Network.Paths[v.Address].Address == "") {
			continue
		}
		// Retained observations for a removed target must not wedge unrelated
		// commands. Only the matching failed receipt may explain revoked policy.
		if !pathMTUAllowed(n.Desired, v.Address) && !(commandMatches && report.Result.State == "failed" && pathMTUAddress(v.Address)) {
			continue
		}
		if len(v.Reason) > 512 || len(v.Interface) > 15 || len(v.Fingerprint) > 64 || time.Since(v.CheckedAt) > 2*time.Minute || time.Until(v.CheckedAt) > time.Minute || (v.CanChange || v.CanRestore) && !glivela.ValidIdentity(v.Fingerprint) || v.Configured < 0 || v.Configured > 65535 || v.Actual < 0 || v.Actual > 65535 || v.InterfaceMTU < 0 || v.InterfaceMTU > 65535 {
			return errors.New("unexpected path observation")
		}
		if len(s.pathMTUReports[cert]) >= 32 && s.pathMTUReports[cert][v.Address].Address == "" {
			return errors.New("path observation limit")
		}
		s.pathMTUReports[cert][v.Address] = v
	}
	return nil
}

func recordPathMTU(settings *NetworkSettings, report *NetworkReport) {
	if settings.Command == nil || settings.Command.PathMTU == nil {
		return
	}
	settings.Paths = maps.Clone(settings.Paths)
	if settings.Paths == nil {
		settings.Paths = map[string]PathMTUObservation{}
	}
	for _, v := range report.Paths {
		if v.Address == settings.Command.PathMTU.Address {
			settings.Paths[v.Address] = v
		}
	}
}

func pathNetworkReport(ctx context.Context, directory string) NetworkReport {
	return NetworkReport{Snapshot: inspectNetwork(ctx, directory), PathMTUSupported: true, Paths: observePathMTUs(ctx, directory)}
}

func runPathMTU(ctx context.Context, client *Client, directory string, command NetworkCommand) NetworkReport {
	result := &NetworkResult{ID: command.ID, State: "failed", Message: "路径授权已变化或控制连接不可用"}
	desired, err := client.currentDesired(ctx)
	if err == nil && command.PathMTU != nil && desired.Validate() == nil && desired.Revision == command.PathMTU.Revision && desired.ConfigSHA256 == command.PathMTU.Hash && pathMTUAllowed(desired, command.PathMTU.Address) {
		return executePathMTU(ctx, directory, command)
	}
	report := pathNetworkReport(ctx, directory)
	report.Result = result
	if command.PathMTU != nil {
		report.Paths = []PathMTUObservation{{Address: command.PathMTU.Address, CheckedAt: time.Now().UTC(), Reason: result.Message}}
	}
	return report
}
