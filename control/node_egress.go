package control

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

type NodeEgressChange struct {
	ID               string               `json:"id"`
	Action           string               `json:"action"`
	ExpectedRevision uint64               `json:"expectedRevision,string"`
	NativeEgress     glivela.EgressPolicy `json:"nativeEgress,omitempty"`
	EgressIP         string               `json:"egressIp,omitempty"`
	ExpectedExit     string               `json:"expectedExit,omitempty"`
}

type NodeEgressView struct {
	ID              string                          `json:"id"`
	Role            string                          `json:"role"`
	Revision        uint64                          `json:"revision,string"`
	RuntimeReady    bool                            `json:"runtimeReady"`
	NativeEgress    glivela.EgressPolicy            `json:"nativeEgress,omitempty"`
	EgressIP        string                          `json:"egressIp,omitempty"`
	ExpectedExit    string                          `json:"expectedExit,omitempty"`
	LinkedEntries   int                             `json:"linkedEntries"`
	BlockedPolicies map[glivela.EgressPolicy]string `json:"blockedPolicies,omitempty"`
	ReadOnlyReason  string                          `json:"readOnlyReason,omitempty"`
}

type nodeEgressError string

func (e nodeEgressError) Error() string { return string(e) }

func (s *Store) nodeEgressViewLocked(node Node) (NodeEgressView, error) {
	v := NodeEgressView{ID: node.ID, Revision: node.Desired.Revision, RuntimeReady: s.availableRuntime(node, time.Now())}
	if node.EntryQuota != nil || node.TransportTail != nil {
		v.ReadOnlyReason = "egress_transition_pending"
	}
	if node.Desired.Entry != nil {
		v.Role, v.NativeEgress = "entry", node.Desired.Entry.NativeEgress
		if v.NativeEgress == "" {
			v.NativeEgress = glivela.EgressAuto
		}
		v.BlockedPolicies = map[glivela.EgressPolicy]string{}
		for _, e := range s.business.material.Endpoints {
			if e.Reality.EntryID == node.ID && realityChangePending(e) {
				v.ReadOnlyReason = "egress_transition_pending"
			}
		}
		for _, c := range s.business.material.ClientChains {
			if c.EntryID != node.ID || !c.Enabled || s.business.material.DeletedClientChains[c.ID] {
				continue
			}
			chain, err := s.business.material.EffectiveClientChain(c)
			if err != nil {
				return v, nodeEgressError("egress_chain_unverified")
			}
			if chain.Transport == "ipv6-ss2022" && (chain.Relay == nil || chain.Relay.Transport != glivela.IPv4RelaySS2022) {
				v.BlockedPolicies[glivela.EgressIPv4Only] = "egress_ipv6_chain_conflict"
			} else {
				v.BlockedPolicies[glivela.EgressIPv6Only] = "egress_ipv4_chain_conflict"
			}
		}
		return v, nil
	}
	if node.Desired.Landing == nil {
		return v, nodeEgressError("egress_unavailable")
	}
	v.Role, v.EgressIP = "landing", node.Desired.Landing.EgressIP
	for _, chain := range s.business.material.ClientChains {
		if chain.Relay != nil && chain.Relay.NodeID == node.ID && chain.Enabled && !s.business.material.DeletedClientChains[chain.ID] {
			v.ReadOnlyReason = "egress_chain_unverified"
		}
	}
	inconsistent := false
	matched := map[string]bool{}
	for _, entry := range s.nodes {
		if entry.Desired.EntryNetwork == nil {
			continue
		}
		for _, peer := range entry.Desired.EntryNetwork.Peers {
			if peer.EgressID != node.ID {
				continue
			}
			if v.LinkedEntries > 0 && v.ExpectedExit != peer.ExpectedExit {
				inconsistent = true
			}
			member, ok := node.RouteEntries[entry.ID]
			if !ok || member.CertificateID != entry.CertificateID || entry.Desired.EntryNetwork.Source == nil || member.Address != entry.Desired.EntryNetwork.Source.Address || peer.Identity.Address != node.Desired.Landing.Address {
				v.ReadOnlyReason = "egress_route_conflict"
			}
			matched[entry.ID] = true
			v.LinkedEntries++
			v.ExpectedExit = peer.ExpectedExit
		}
	}
	if inconsistent {
		v.ExpectedExit = ""
		v.ReadOnlyReason = "egress_route_conflict"
	}
	for id := range node.RouteEntries {
		if !matched[id] {
			v.ReadOnlyReason = "egress_route_conflict"
		}
	}
	return v, nil
}

// ChangeNodeEgress edits only the owned exit policy. The browser never receives
// or resubmits credentials, full plans or certificate identities.
func (s *Store) ChangeNodeEgress(ctx context.Context, input NodeEgressChange) (NodeEgressView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := nodeEgressError("egress_unavailable")
	if err := ctx.Err(); err != nil {
		return NodeEgressView{}, err
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil || !glivela.ValidIdentifier(input.ID) || s.entryRetiredLocked(input.ID) {
		return NodeEgressView{}, invalid
	}
	var certificate string
	var node Node
	for key, candidate := range s.nodes {
		if candidate.ID == input.ID {
			certificate, node = key, candidate
		}
	}
	if certificate == "" {
		return NodeEgressView{}, invalid
	}
	view, err := s.nodeEgressViewLocked(node)
	if err != nil {
		return NodeEgressView{}, err
	}
	if input.Action == "inspect" {
		return view, nil
	}
	if input.Action != "apply" || input.ExpectedRevision == 0 || input.ExpectedRevision != node.Desired.Revision || input.ExpectedRevision == math.MaxUint64 {
		return view, nodeEgressError("egress_revision_changed")
	}
	if view.ReadOnlyReason != "" {
		return view, nodeEgressError(view.ReadOnlyReason)
	}
	next := s.copy()
	desired := node.Desired.clone()
	if desired.Entry != nil {
		if input.NativeEgress == "" || input.NativeEgress.Validate() != nil || input.EgressIP != "" || input.ExpectedExit != "" {
			return view, nodeEgressError("egress_invalid_policy")
		}
		if input.NativeEgress == view.NativeEgress {
			return view, nil
		}
		if reason := view.BlockedPolicies[input.NativeEgress]; reason != "" {
			return view, nodeEgressError(reason)
		}
		desired.Entry.NativeEgress = input.NativeEgress
		desired.Entry.Revision++
		node.Desired, err = newEntryDesiredVersion(*desired.Entry, *desired.EntryNetwork, desired.EntryRenderVersion)
	} else {
		if input.NativeEgress != "" || !landing.ValidEgressIP(input.EgressIP) {
			return view, nodeEgressError("egress_invalid_address")
		}
		address, _ := netip.ParseAddr(input.EgressIP)
		// Entry startup gates probe an exact public exit only at activation.
		// A simultaneous entry/landing update can permanently close that gate
		// when the entry applies first. This local editor must not orchestrate
		// a cross-node exit migration or rewrite any verifier expectation.
		oldAddress, _ := netip.ParseAddr(view.EgressIP)
		if view.LinkedEntries > 0 && (input.ExpectedExit != view.ExpectedExit || address.Is4() != oldAddress.Is4() || !address.IsPrivate() && address.String() != view.ExpectedExit) {
			return view, nodeEgressError("egress_bound_exit_conflict")
		}
		exit, exitErr := netip.ParseAddr(input.ExpectedExit)
		if view.LinkedEntries > 0 && (exitErr != nil || exit.String() != input.ExpectedExit || !landing.PublicIP(exit) || address.Is4() != exit.Is4()) {
			return view, nodeEgressError("egress_expected_exit_required")
		}
		if view.LinkedEntries == 0 && input.ExpectedExit != "" {
			return view, nodeEgressError("egress_invalid_address")
		}
		if input.EgressIP == view.EgressIP && input.ExpectedExit == view.ExpectedExit {
			return view, nil
		}
		if address.Is6() {
			for _, source := range desired.Landing.Sources {
				if !source.TCPOnly {
					return view, nodeEgressError("egress_udp_conflict")
				}
			}
		}
		desired.Landing.EgressIP = input.EgressIP
		desired.Landing.Revision++
		desired.DesiredArtifact, err = desired.Landing.ArtifactVersion(desired.LandingRenderVersion)
		node.Desired = desired
		node.Checks = nil
	}
	if err != nil || node.Desired.Validate() != nil {
		return view, nodeEgressError("egress_invalid_policy")
	}
	node.Receipt, node.ReportedAt, node.EntryHealthBarrierAt = nil, time.Time{}, time.Time{}
	next[certificate] = node
	if node.Desired.Entry != nil {
		invalidateEntryChecks(next, node.ID)
	}
	projected, changed, err := projectBusinessEntries(next, s.business.material, time.Now())
	if err != nil || changed {
		return view, nodeEgressError("egress_projection_pending")
	}
	if err := validateEnrollmentRoles(projected); err != nil {
		return view, invalid
	}
	if err := s.commit(projected); err != nil {
		return view, errors.New("control: egress persistence not confirmed")
	}
	return s.nodeEgressViewLocked(s.nodes[certificate])
}
