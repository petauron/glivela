package control

import (
	"context"
	"errors"
	"math"
	"net"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

// RealityChangeInput edits only an owned endpoint's target and exact SNI.
// Public ingress acceptance is operator-attested, separately from node readiness.
type RealityChangeInput struct {
	InitialRepair      *glivela.RealityInitialRepair `json:"initialRepair,omitempty"`
	Reason             string                        `json:"reason"`
	EntryID            string                        `json:"entryId"`
	ExpectedRevision   uint64                        `json:"expectedRevision,string"`
	Action             string                        `json:"action"`
	TargetHost         string                        `json:"targetHost"`
	TargetIP           string                        `json:"targetIp"`
	LocalTLSOrigin     bool                          `json:"localTlsOrigin"`
	ServerName         string                        `json:"serverName"`
	EvidenceSHA256     string                        `json:"evidenceSha256"`
	VerifiedAt         time.Time                     `json:"verifiedAt"`
	PublicationChecked bool                          `json:"publicationChecked"`
}

type RealityChangeView struct {
	RepairInitial bool                          `json:"repairInitial"`
	CertificateID string                        `json:"certificateId"`
	ConfigSHA256  string                        `json:"configSha256"`
	PreviewMihomo string                        `json:"previewMihomo,omitempty"`
	PreviewLink   string                        `json:"previewLink,omitempty"`
	EntryID       string                        `json:"entryId"`
	Revision      uint64                        `json:"revision,string"`
	Target        string                        `json:"target"`
	ServerNames   []string                      `json:"serverNames"`
	State         string                        `json:"state"`
	RuntimeReady  bool                          `json:"runtimeReady"`
	History       []glivela.RealityTargetChange `json:"history"`
}

func (s *Store) ChangeRealityTarget(ctx context.Context, input RealityChangeInput) (RealityChangeView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: REALITY target change refused; refresh the endpoint and recovery state")
	if err := ctx.Err(); err != nil {
		return RealityChangeView{}, err
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil || !glivela.ValidIdentifier(input.EntryID) {
		return RealityChangeView{}, invalid
	}
	certificate := ""
	var node Node
	for key, n := range s.nodes {
		if n.ID == input.EntryID {
			certificate, node = key, n
		}
	}
	if certificate == "" || node.Desired.Entry == nil || node.Desired.EntryNetwork == nil || node.EntryQuota != nil || node.TransportTail != nil || input.Action != "inspect" && (node.Desired.Revision != input.ExpectedRevision || input.ExpectedRevision == math.MaxUint64) {
		return RealityChangeView{}, invalid
	}
	material := s.business.material
	index := slices.IndexFunc(material.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == input.EntryID })
	if index < 0 || material.Endpoints[index].Retired || !material.Endpoints[index].VLESSEnabled {
		return RealityChangeView{}, invalid
	}
	now := time.Now().UTC()
	if input.Action == "inspect" {
		view := realityChangeView(node, material.Endpoints[index], now)
		view.RepairInitial = s.initialRealityTargetRepairable(node, material.Endpoints[index], now)
		return view, nil
	}
	material.Endpoints = slices.Clone(material.Endpoints)
	endpoint := &material.Endpoints[index]
	endpoint.RealityChanges = slices.Clone(endpoint.RealityChanges)
	var last *glivela.RealityTargetChange
	if len(endpoint.RealityChanges) > 0 {
		last = &endpoint.RealityChanges[len(endpoint.RealityChanges)-1]
	}
	if input.InitialRepair != nil && input.Action != "repair-initial" {
		return RealityChangeView{}, invalid
	}
	switch input.Action {
	case "apply", "repair-initial":
		if input.Action == "repair-initial" {
			proof := input.InitialRepair
			if s.speedHub != nil && s.speedHub.online(certificate) || !s.initialRealityTargetRepairable(node, *endpoint, now) || proof == nil || proof.CertificateID != certificate || proof.ConfigSHA256 != node.Desired.ConfigSHA256 {
				return RealityChangeView{}, invalid
			}
			verified, err := time.Parse(time.RFC3339Nano, proof.VerifiedAt)
			created, createdErr := time.Parse(time.RFC3339Nano, endpoint.CreatedAt)
			if createdErr != nil || verified.Before(created) || err != nil || verified.After(now) || now.Sub(verified) > 15*time.Minute || !glivela.ValidIdentity(proof.EvidenceSHA256) {
				return RealityChangeView{}, invalid
			}
			// Only the wrong port can change. The administrator attests that the
			// identified worker is stopped and has never activated a runtime.
			input.TargetHost, input.ServerName = endpoint.Reality.ServerNames[0], endpoint.Reality.ServerNames[0]
			input.TargetIP, input.LocalTLSOrigin = "", true
		} else if !s.realityTargetRuntimeReady(node, *endpoint, now) || !realityNodeReady(node, *endpoint, now) {
			return RealityChangeView{}, invalid
		}
		if len(endpoint.RealityChanges) >= 32 || last != nil && (last.State == "pending" || last.State == "reverting") {
			return RealityChangeView{}, invalid
		}
		enabled := slices.ContainsFunc(node.Desired.Entry.Credentials, func(c glivela.CredentialMaterial) bool {
			return c.Credential.Enabled && c.Credential.Kind == glivela.NativeCredential && c.Credential.EntryID == input.EntryID
		})
		port := "443"
		if input.LocalTLSOrigin {
			if input.TargetIP != "" || input.TargetHost != input.ServerName {
				return RealityChangeView{}, invalid
			}
			input.TargetIP, port, _ = net.SplitHostPort(glivela.ManagedLocalTLSTarget)
		}
		if !enabled || !glivela.ValidRealityTargetPin(net.JoinHostPort(input.TargetHost, port), input.TargetIP) {
			return RealityChangeView{}, invalid
		}
		candidate := endpoint.Reality
		candidate.Target = net.JoinHostPort(input.TargetHost, port)
		candidate.ServerNames = []string{input.ServerName}
		if candidate.Validate() != nil || candidate.Target == endpoint.Reality.Target && input.TargetIP == endpoint.TargetIP && slices.Equal(candidate.ServerNames, endpoint.Reality.ServerNames) {
			return RealityChangeView{}, invalid
		}
		endpoint.RealityChanges = append(endpoint.RealityChanges, glivela.RealityTargetChange{PreviousTarget: endpoint.Reality.Target, PreviousTargetIP: endpoint.TargetIP, PreviousServerNames: slices.Clone(endpoint.Reality.ServerNames), Target: candidate.Target, TargetIP: input.TargetIP, ServerName: input.ServerName, State: "pending", ChangedAt: now.Format(time.RFC3339Nano)})
		if input.InitialRepair != nil {
			proof := *input.InitialRepair
			endpoint.RealityChanges[len(endpoint.RealityChanges)-1].InitialRepair = &proof
		}
		endpoint.Reality = candidate
		endpoint.TargetIP = input.TargetIP
	case "revert":
		if last == nil || last.InitialRepair != nil || last.State != "pending" || len(input.Reason) == 0 || len(input.Reason) > 256 {
			return RealityChangeView{}, invalid
		}
		endpoint.Reality.Target = last.PreviousTarget
		endpoint.Reality.ServerNames = slices.Clone(last.PreviousServerNames)
		endpoint.TargetIP = last.PreviousTargetIP
		last.State = "reverting"
		last.RevertedAt = now.Format(time.RFC3339Nano)
		last.Reason = input.Reason
	case "accept":
		if last == nil || last.State != "pending" && last.State != "reverting" || !s.realityTargetRuntimeReady(node, *endpoint, now) || !realityNodeReady(node, *endpoint, now) || node.Receipt == nil || validateEntryHealth(node.Desired, node.Receipt.EntryHealth) != nil || !input.PublicationChecked || !glivela.ValidIdentity(input.EvidenceSHA256) || input.VerifiedAt.IsZero() || input.VerifiedAt.After(now) || now.Sub(input.VerifiedAt) > 15*time.Minute {
			return RealityChangeView{}, invalid
		}
		barrier := last.ChangedAt
		if last.State == "reverting" {
			barrier = last.RevertedAt
		}
		changedAt, err := time.Parse(time.RFC3339Nano, barrier)
		startedAt, startErr := time.Parse(time.RFC3339Nano, node.Receipt.Traffic.StartedAt)
		if err != nil || startErr != nil || input.VerifiedAt.Before(changedAt) || input.VerifiedAt.Before(startedAt) {
			return RealityChangeView{}, invalid
		}
		last.EvidenceSHA256 = input.EvidenceSHA256
		last.VerifiedAt = input.VerifiedAt.Format(time.RFC3339Nano)
		if last.State == "reverting" {
			last.State = "reverted"
		} else {
			last.State = "accepted"
		}
		if err := s.saveOwnedBusinessLocked(material); err != nil {
			return RealityChangeView{}, err
		}
		return realityChangeView(node, *endpoint, now), nil
	default:
		return RealityChangeView{}, invalid
	}
	if endpoint.DesiredRevision == math.MaxUint64 {
		return RealityChangeView{}, invalid
	}
	endpoint.DesiredRevision++
	endpoint.UpdatedAt = now.Format(time.RFC3339Nano)
	if err := material.Validate(); err != nil {
		return RealityChangeView{}, invalid
	}
	nodes := s.copy()
	desired := node.Desired.clone()
	found := false
	for i, e := range desired.Entry.RealityEndpoints {
		if e.ID == endpoint.Reality.ID {
			projectedEndpoint, projectionErr := ownedRealityForNode(node, *endpoint)
			if projectionErr != nil {
				return RealityChangeView{}, invalid
			}
			desired.Entry.RealityEndpoints[i] = projectedEndpoint
			found = true
		}
	}
	if !found {
		return RealityChangeView{}, invalid
	}
	desired.Entry.Revision++
	var err error
	node.Desired, err = newEntryDesiredVersion(*desired.Entry, *desired.EntryNetwork, desired.EntryRenderVersion)
	if err != nil {
		return RealityChangeView{}, invalid
	}
	node.Receipt = nil
	node.ReportedAt = time.Time{}
	node.EntryHealthBarrierAt = time.Time{}
	nodes[certificate] = node
	invalidateEntryChecks(nodes, node.ID)
	projected, _, err := projectBusinessEntries(nodes, material, now)
	if err != nil {
		return RealityChangeView{}, err
	}
	if input.Action == "repair-initial" {
		for key, other := range s.nodes {
			if key != certificate && !reflect.DeepEqual(projected[key], other) {
				return RealityChangeView{}, invalid
			}
		}
	}
	if err = s.saveOwnedBusinessLocked(material); err != nil {
		return RealityChangeView{}, err
	}
	if err = s.commit(projected); err != nil {
		return RealityChangeView{}, err
	}
	return realityChangeView(projected[certificate], *endpoint, now), nil
}

func realityChangeView(node Node, endpoint glivela.ImportEndpoint, now time.Time) RealityChangeView {
	state := "unchanged"
	if len(endpoint.RealityChanges) > 0 {
		state = endpoint.RealityChanges[len(endpoint.RealityChanges)-1].State
	}
	ready := realityNodeReady(node, endpoint, now)
	view := RealityChangeView{CertificateID: node.CertificateID, ConfigSHA256: node.Desired.ConfigSHA256, EntryID: node.ID, Revision: node.Desired.Revision, Target: endpoint.Reality.Target, ServerNames: slices.Clone(endpoint.Reality.ServerNames), State: state, RuntimeReady: ready, History: append([]glivela.RealityTargetChange{}, endpoint.RealityChanges...)}
	// A private candidate link allows actual client acceptance while the official
	// subscription remains fenced. It reuses an enabled identity, never mints one.
	if ready && (state == "pending" || state == "reverting") {
		for _, c := range node.Desired.Entry.Credentials {
			if c.Credential.Enabled && c.Credential.Kind == glivela.NativeCredential && c.Credential.EntryID == node.ID {
				view.PreviewLink, _ = glivela.LinkForCredential(endpoint.Reality, c, "REALITY candidate")
				preview, _, err := glivela.RenderMihomo([]glivela.NativeEntry{{Material: c, Protocol: glivela.VLESSReality, Link: view.PreviewLink}}, c.Credential.AccountID, glivela.FixedMode, nil, nil)
				if err == nil {
					view.PreviewMihomo = string(preview)
				}
				break
			}
		}
	}
	return view
}

// Maintenance suppresses publication, but must not prevent an administrator
// repairing that entrance. Exhaustion and retired/stale runtimes stay fenced.
func (s *Store) realityTargetRuntimeReady(node Node, endpoint glivela.ImportEndpoint, now time.Time) bool {
	if endpoint.TotalBytes > 0 && endpoint.UsedBytes >= endpoint.TotalBytes {
		return false
	}
	if s.suspended(node.ID, now) {
		pause, ok := s.effectiveAvailability(node.ID)
		if !ok || pause.Reason != "maintenance" {
			return false
		}
	}
	return s.observedRuntimeReady(node, now)
}

func realityNodeReady(node Node, endpoint glivela.ImportEndpoint, now time.Time) bool {
	return runtimeFresh(node, now) && realityNodeMatches(node, endpoint) && node.Receipt.EntryHealth != nil && validateEntryHealth(node.Desired, node.Receipt.EntryHealth) == nil && node.Receipt.Traffic != nil && validateEntryTraffic(node.Desired, node.Receipt.Traffic) == nil
}

func realityNodeMatches(node Node, endpoint glivela.ImportEndpoint) bool {
	expected, err := ownedRealityForNode(node, endpoint)
	return err == nil && node.Desired.Entry != nil && slices.ContainsFunc(node.Desired.Entry.RealityEndpoints, func(e glivela.RealityEndpoint) bool { return reflect.DeepEqual(e, expected) })
}

// Rebuild nodes.json after a business commit whose projection write was lost.
// Only the exact latest transition is authorized; unrelated identity drift fails.
func authorizedRealityProjection(node Node, current glivela.RealityEndpoint, endpoint glivela.ImportEndpoint) bool {
	if len(endpoint.RealityChanges) == 0 {
		return false
	}
	last := endpoint.RealityChanges[len(endpoint.RealityChanges)-1]
	expected, err := ownedRealityForNode(node, endpoint)
	if err != nil {
		return false
	}
	actualTarget, actualNames := current.Target, current.ServerNames
	current.Target, current.ServerNames = expected.Target, expected.ServerNames
	if !reflect.DeepEqual(current, expected) {
		return false
	}
	before := pinnedRealityTarget(last.PreviousTarget, last.PreviousTargetIP)
	after := pinnedRealityTarget(last.Target, last.TargetIP)
	return (actualTarget == before || actualTarget == last.PreviousTarget) && slices.Equal(actualNames, last.PreviousServerNames) || (actualTarget == after || actualTarget == last.Target) && slices.Equal(actualNames, []string{last.ServerName})
}
