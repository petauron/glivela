package control

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"math"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
)

// EndpointRegistration adds a fresh entry to the owned business. It is an
// authenticated administrator operation, not a node-supplied topology update.
// Stable caller-selected IDs make retries reuse the same credentials/ledger.
type EndpointRegistration struct {
	CertificateID string                    `json:"certificateId"`
	NativeEgress  glivela.EgressPolicy      `json:"nativeEgress"`
	Endpoint      glivela.ImportEndpoint    `json:"endpoint"`
	NodeID        string                    `json:"nodeId"`
	Node          glivela.ImportNode        `json:"node"`
	Application   glivela.ImportApplication `json:"application"`
	Service       glivela.ImportService     `json:"service"`
	Accounts      []string                  `json:"accounts"`
}

func (s *Store) RegisterEndpoint(ctx context.Context, input EndpointRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: fresh endpoint registration refused")
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil || len(input.Accounts) == 0 || len(input.Accounts) > 1024 {
		return invalid
	}
	e := input.Endpoint
	e.Reality.ServerNames = slices.Clone(e.Reality.ServerNames)
	e.Reality.ShortIDs = slices.Clone(e.Reality.ShortIDs)
	e.SourcePeerJSON = bytes.Clone(e.SourcePeerJSON)
	input.Node.PeerJSON = bytes.Clone(input.Node.PeerJSON)
	input.Node.EgressAddressesJSON = bytes.Clone(input.Node.EgressAddressesJSON)
	entry, service := e.Reality.EntryID, e.ServiceID
	if !glivela.ValidIdentity(input.CertificateID) || input.NativeEgress == "" || input.NativeEgress.Validate() != nil || !glivela.ValidIdentifier(input.NodeID) || entry == input.NodeID || e.Validate() != nil || e.PreviousAdvertiseHost != "" || e.UsedBytes != 0 || e.AppliedRevision != 0 || e.DesiredRevision != 1 || e.Retired || e.LegacyRetired || e.HistoricalHealthy || e.RuntimeCertificateID != "" || e.RuntimeConfigSHA256 != "" || e.PreviousStatus != "pending" || len(e.RealityChanges) != 0 || e.Hysteria != nil || input.Application.NodeID != input.NodeID || input.Application.Runtime != "host" || input.Service.ApplicationID != entry {
		return invalid
	}
	for cert, node := range s.nodes {
		if (node.ID == entry || cert == input.CertificateID) && (node.ID != entry || cert != input.CertificateID || node.Desired.Entry == nil || node.Desired.Entry.NativeEgress != input.NativeEgress) {
			return invalid
		}
	}
	next := s.business.material
	next.References.Nodes = maps.Clone(next.References.Nodes)
	next.References.Applications = maps.Clone(next.References.Applications)
	next.References.Services = maps.Clone(next.References.Services)
	index := slices.IndexFunc(next.Endpoints, func(x glivela.ImportEndpoint) bool {
		return x.Reality.EntryID == entry || x.Reality.ID == e.Reality.ID || x.ServiceID == service
	})
	if index >= 0 {
		old := next.Endpoints[index]
		if old.Reality.EntryID != entry || !reflect.DeepEqual(old.Reality, e.Reality) || old.ServiceID != service || old.Retired || old.TotalBytes != e.TotalBytes || old.ResetDay != e.ResetDay || old.TargetIP != e.TargetIP || old.VLESSEnabled != e.VLESSEnabled || !reflect.DeepEqual(next.References.Nodes[input.NodeID], input.Node) || next.References.Applications[entry] != input.Application || next.References.Services[service] != input.Service {
			return invalid
		}
		if old.QuotaAppliedEnabled != e.QuotaAppliedEnabled {
			// Correct only an unused, unlimited initial registration. A retry
			// must never reopen an exhausted quota or change an active entry.
			if !e.QuotaAppliedEnabled || old.TotalBytes != 0 || old.UsedBytes != 0 || old.ResetDay != 0 || old.DesiredRevision != 1 || old.AppliedRevision != 0 || old.PreviousStatus != "pending" || old.HistoricalHealthy || old.LegacyRetired || old.RuntimeCertificateID != "" || old.RuntimeConfigSHA256 != "" {
				return invalid
			}
			for _, account := range next.Plan.Accounts {
				for _, credential := range account.Credentials {
					if credential.EntryID != entry {
						continue
					}
					counter := next.TrafficCounters[credential.ID]
					if counter.UploadBytes != 0 || counter.DownloadBytes != 0 || counter.RawUploadBytes != 0 || counter.RawDownloadBytes != 0 {
						return invalid
					}
				}
			}
			next.Endpoints = slices.Clone(next.Endpoints)
			next.Endpoints[index].QuotaAppliedEnabled = true
		}
	} else {
		if _, exists := next.References.Applications[entry]; exists {
			return invalid
		}
		if _, exists := next.References.Services[service]; exists {
			return invalid
		}
		if existing, exists := next.References.Nodes[input.NodeID]; exists && !reflect.DeepEqual(existing, input.Node) {
			return invalid
		}
		for _, n := range s.nodes {
			if n.ID == entry {
				return invalid
			}
		}
		next.Endpoints = append(slices.Clone(next.Endpoints), e)
		next.References.Nodes[input.NodeID] = input.Node
		next.References.Applications[entry] = input.Application
		next.References.Services[service] = input.Service
	}
	next.ProtocolSecrets = maps.Clone(next.ProtocolSecrets)
	next.TrafficCounters = maps.Clone(next.TrafficCounters)
	accounts := slices.Clone(next.Plan.Accounts)
	for i, id := range input.Accounts {
		if slices.Contains(input.Accounts[:i], id) {
			return invalid
		}
		at := slices.IndexFunc(accounts, func(a glivela.ImportAccount) bool { return a.Account.ID == id })
		if at < 0 {
			return invalid
		}
		a := accounts[at]
		if slices.ContainsFunc(a.Credentials, func(c glivela.Credential) bool { return c.EntryID == entry && c.Kind == glivela.NativeCredential }) {
			continue
		}
		if a.Account.DesiredRevision == math.MaxUint64 {
			return invalid
		}
		protocol, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		credentialID, err := uuid.NewRandom()
		if err != nil {
			return err
		}
		credential := glivela.Credential{ID: credentialID.String(), AccountID: id, EntryID: entry, Kind: glivela.NativeCredential, User: credentialID.String(), Identity: glivela.Identity(protocol.String()), Enabled: true}
		a.Credentials = append(slices.Clone(a.Credentials), credential)
		a.Usage = append(slices.Clone(a.Usage), glivela.UsageMember{CredentialID: credential.ID, Active: true})
		a.Account.DesiredRevision++
		accounts[at] = a
		next.ProtocolSecrets[credential.ID] = protocol.String()
		next.TrafficCounters[credential.ID] = glivela.ImportTrafficCounters{}
	}
	var err error
	next.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		return invalid
	}
	if next.Validate() != nil {
		return invalid
	}
	// Material is committed first. Missing runtime projections remain unpublished
	// and are safely rebuilt with these same identities on retry or enrollment.
	projected := s.copy()
	if _, exists := projected[input.CertificateID]; !exists {
		credentials, _, err := effectiveBusinessCredentials(next, time.Now())
		if err != nil {
			return err
		}
		plan := glivela.XrayPlan{Revision: 1, NativeEgress: input.NativeEgress, RealityEndpoints: []glivela.RealityEndpoint{pinnedImportedReality(e)}}
		for _, account := range next.Plan.Accounts {
			for _, c := range account.Credentials {
				if c.EntryID == entry {
					plan.Credentials = append(plan.Credentials, credentials[c.ID])
				}
			}
		}
		desired, err := NewEntryDesired(plan, EntryNetwork{})
		if err != nil {
			return err
		}
		projected[input.CertificateID] = Node{ID: entry, CertificateID: input.CertificateID, Desired: desired}
	}
	for _, id := range input.Accounts {
		projected, err = projectAccountCreation(projected, next, id)
		if err != nil {
			return err
		}
	}
	if validateEnrollmentRoles(projected) != nil {
		return invalid
	}
	if err := s.saveOwnedBusinessLocked(next); err != nil {
		return err
	}
	if reflect.DeepEqual(projected, s.nodes) {
		return nil
	}
	return s.commit(projected)
}

func runtimeHostID(m glivela.ImportMaterial, node Node) string {
	if node.Desired.Entry != nil {
		return m.References.Applications[node.ID].NodeID
	}
	if _, ok := m.References.Nodes[node.ID]; ok {
		return node.ID
	}
	return ""
}
