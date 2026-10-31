package control

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/petauron/glivela"
)

// PrivateListenerChange only switches the owned node's private REALITY port.
// It does not alter published addresses, credentials or the business ledger.
type PrivateListenerChange struct {
	EntryID          string `json:"entryId"`
	ExpectedRevision uint64 `json:"expectedRevision,string"`
	Action           string `json:"action"`
	Port             int    `json:"port"`
}

type PrivateListenerView struct {
	EntryID      string `json:"entryId"`
	Revision     uint64 `json:"revision,string"`
	Port         int    `json:"port"`
	RuntimeReady bool   `json:"runtimeReady"`
}

func privateBackendAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value && (address.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(address))
}

// The override lives with the owned node's execution plan, which is written in
// one atomic nodes.json commit. The encrypted business source and its traffic
// counters are never rewritten to change a host-specific listener port.
func ownedRealityForNode(node Node, endpoint glivela.ImportEndpoint) (glivela.RealityEndpoint, error) {
	expected := pinnedImportedReality(endpoint)
	if node.PrivateListenerPort == 0 {
		return expected, nil
	}
	if node.PrivateListenerPort != glivela.DefaultRealityPort || endpoint.Reality.ListenPort != glivela.RealityBackendPort || !privateBackendAddress(expected.ListenAddress) {
		return glivela.RealityEndpoint{}, errors.New("control: invalid owned private listener")
	}
	expected.ListenPort = node.PrivateListenerPort
	return expected, nil
}

func validPrivateListenerOverride(node Node) bool {
	if node.PrivateListenerPort == 0 {
		return true
	}
	if node.PrivateListenerPort != glivela.DefaultRealityPort || node.Desired.Entry == nil || len(node.Desired.Entry.RealityEndpoints) != 1 {
		return false
	}
	endpoint := node.Desired.Entry.RealityEndpoints[0]
	return endpoint.ListenPort == node.PrivateListenerPort && privateBackendAddress(endpoint.ListenAddress)
}

func (s *Store) ChangePrivateListener(ctx context.Context, input PrivateListenerChange) (PrivateListenerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: private listener change refused")
	if err := ctx.Err(); err != nil {
		return PrivateListenerView{}, err
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil || !glivela.ValidIdentifier(input.EntryID) {
		return PrivateListenerView{}, invalid
	}
	certificate := ""
	var node Node
	for key, candidate := range s.nodes {
		if candidate.ID == input.EntryID {
			certificate, node = key, candidate
		}
	}
	if certificate == "" || node.Desired.Entry == nil || node.Desired.EntryNetwork == nil || node.EntryQuota != nil || node.TransportTail != nil || len(node.Desired.Entry.RealityEndpoints) != 1 {
		return PrivateListenerView{}, invalid
	}
	index := slices.IndexFunc(s.business.material.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == input.EntryID })
	if index < 0 {
		return PrivateListenerView{}, invalid
	}
	endpoint := s.business.material.Endpoints[index]
	if endpoint.Retired || !endpoint.VLESSEnabled || realityChangePending(endpoint) || endpoint.Reality.ListenPort != glivela.RealityBackendPort || !privateBackendAddress(endpoint.Reality.ListenAddress) || !realityNodeMatches(node, endpoint) {
		return PrivateListenerView{}, invalid
	}
	now := time.Now().UTC()
	view := func(n Node) PrivateListenerView {
		return PrivateListenerView{EntryID: n.ID, Revision: n.Desired.Revision, Port: n.Desired.Entry.RealityEndpoints[0].ListenPort, RuntimeReady: realityNodeReady(n, endpoint, now)}
	}
	if input.Action == "inspect" {
		return view(node), nil
	}
	if input.Action != "apply" || input.ExpectedRevision != node.Desired.Revision || input.ExpectedRevision == math.MaxUint64 || (input.Port != glivela.DefaultRealityPort && input.Port != glivela.RealityBackendPort) {
		return PrivateListenerView{}, invalid
	}
	if node.Desired.Entry.RealityEndpoints[0].ListenPort == input.Port {
		return view(node), nil
	}
	// Reversion is allowed even after the new listener failed to start.
	if input.Port == glivela.DefaultRealityPort && (!s.availableRuntime(node, now) || !realityNodeReady(node, endpoint, now)) {
		return PrivateListenerView{}, invalid
	}
	desired := node.Desired.clone()
	desired.Entry.RealityEndpoints[0].ListenPort = input.Port
	desired.Entry.Revision++
	var err error
	node.Desired, err = NewEntryDesired(*desired.Entry, *desired.EntryNetwork)
	if err != nil {
		return PrivateListenerView{}, invalid
	}
	node.PrivateListenerPort = 0
	if input.Port == glivela.DefaultRealityPort {
		node.PrivateListenerPort = input.Port
	}
	node.Receipt = nil
	node.ReportedAt, node.EntryHealthBarrierAt = time.Time{}, time.Time{}
	if !validPrivateListenerOverride(node) {
		return PrivateListenerView{}, invalid
	}
	next := s.copy()
	next[certificate] = node
	invalidateEntryChecks(next, node.ID)
	projected, changed, err := projectBusinessEntries(next, s.business.material, now)
	if err != nil || changed {
		return PrivateListenerView{}, errors.New("control: pending business projection must be resolved first")
	}
	if err := s.commit(projected); err != nil {
		return PrivateListenerView{}, err
	}
	return view(projected[certificate]), nil
}
