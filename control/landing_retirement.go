package control

import (
	"context"
	"errors"
	"maps"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

type RetireLandingChange struct {
	hostID                       string
	ID                           string `json:"id"`
	CertificateID                string `json:"certificateId"`
	ExpectedRevision             uint64 `json:"expectedRevision,string"`
	ExpectedAvailabilityRevision uint64 `json:"expectedAvailabilityRevision,string"`
	Confirmation                 string `json:"confirmation"`
	ConfirmHostReturned          bool   `json:"confirmHostReturned"`
}

// RetireLanding is an explicit administrative revocation for a returned host.
// A receipt from that host cannot prove an uninstall and is not required here.
// Persist the revocation before changing recoverable runtime projections.
func (s *Store) RetireLanding(ctx context.Context, change RetireLandingChange) error {
	return s.retireReturnedNode(ctx, change, false)
}

// RetireReturnedEntry revokes a confirmed returned host; it never invents an offline receipt.
func (s *Store) RetireReturnedEntry(ctx context.Context, change RetireLandingChange) error {
	return s.retireReturnedNode(ctx, change, true)
}

func (s *Store) retireReturnedNode(ctx context.Context, change RetireLandingChange, entry bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	refused := errors.New("control: landing retirement refused")
	if ctx.Err() != nil || !change.ConfirmHostReturned || change.Confirmation != change.ID ||
		!glivela.ValidIdentifier(change.ID) || !glivela.ValidIdentity(change.CertificateID) || change.ExpectedRevision == 0 ||
		s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return refused
	}
	retired, retry := s.business.material.RetiredLandings[change.ID]
	if retry {
		change.hostID = retired.HostID
		if retired.CertificateID != change.CertificateID || retired.Revision != change.ExpectedRevision {
			return refused
		}
	} else {
		if change.ExpectedAvailabilityRevision != s.availability.Revision {
			return refused
		}
		pause, ok := s.availability.Nodes[change.ID]
		if !ok || pause.Reason != "maintenance" || !pause.ResumeAt.IsZero() {
			return refused
		}
		node, ok := s.nodes[change.CertificateID]
		if !ok || node.ID != change.ID || (node.Desired.Entry != nil) != entry || node.Desired.Revision != change.ExpectedRevision || node.TransportTail != nil {
			return refused
		}
		if entry && (time.Since(pause.ChangedAt) < 5*time.Minute || !node.ReportedAt.IsZero() && time.Since(node.ReportedAt) < 5*time.Minute || s.speedHub != nil && s.speedHub.online(change.CertificateID)) {
			return refused
		}
		change.hostID = runtimeHostID(s.business.material, node)
		if change.hostID == "" {
			change.hostID = change.ID
		}
		// Never remove another role sharing this host.
		for _, other := range s.nodes {
			if other.ID != change.ID && runtimeHostID(s.business.material, other) == change.hostID {
				return refused
			}
		}
	}
	now := time.Now().UTC()
	if s.speedFault {
		return refused
	}
	for _, job := range s.speedJobs {
		if (job.Request.EntryID == change.ID || job.Request.LandingID == change.ID) && !job.View.CleanupConfirmed && now.Before(job.View.StartedAt.Add(speedLease+15*time.Second)) {
			return refused
		}
	}
	next, removed, err := retiredNodeMaterial(s.business.material, change, entry)
	if err != nil {
		return err
	}
	projected, _, err := projectBusinessEntries(s.nodes, next, now)
	if err != nil {
		return err
	}
	// Presentation is non-authoritative. Removing disabled labels first is safe
	// on failure, and prevents dangling names from blocking a restart after commit.
	if err := s.cleanLandingPresentationLocked(change.ID, removed); err != nil {
		return err
	}
	if !retry {
		if err := s.saveOwnedBusinessLocked(next); err != nil {
			return err
		}
	}
	if err := s.commit(projected); err != nil {
		return err
	}
	if err := s.cleanLandingHistoryLocked(change.ID); err != nil {
		return err
	}
	if entry {
		if _, found := s.availability.Nodes[change.ID]; found {
			if s.availability.Revision == math.MaxUint64 {
				return errors.New("control: availability revision exhausted")
			}
			v := availabilityState{Version: 1, Revision: s.availability.Revision + 1, Nodes: maps.Clone(s.availability.Nodes)}
			delete(v.Nodes, change.ID)
			if err := v.validate(); err != nil {
				return err
			}
			if err := writeControlState(filepath.Join(filepath.Dir(s.path), "availability.json"), v); err != nil {
				return err
			}
			s.availability = v
		}
	}
	return nil
}

func retiredLandingMaterial(m glivela.ImportMaterial, change RetireLandingChange) (glivela.ImportMaterial, map[string]bool, error) {
	return retiredNodeMaterial(m, change, false)
}

func retiredNodeMaterial(m glivela.ImportMaterial, change RetireLandingChange, entry bool) (glivela.ImportMaterial, map[string]bool, error) {
	refused := errors.New("control: disable dependent client chains and server routes first")
	for _, endpoint := range m.Endpoints {
		if endpoint.Reality.EntryID == change.ID && !entry {
			return m, nil, refused
		}
	}
	next := m
	next.Endpoints = slices.DeleteFunc(slices.Clone(m.Endpoints), func(e glivela.ImportEndpoint) bool { return entry && e.Reality.EntryID == change.ID })
	next.ServerTransports = maps.Clone(m.ServerTransports)
	removed := map[string]bool{}
	if entry {
		removed[change.ID] = true
		for id, resource := range next.ServerTransports {
			if resource.EntryID == change.ID {
				delete(next.ServerTransports, id)
				removed[id] = true
			} else if resource.EgressID == change.ID || resource.Peer.Relay != nil && resource.Peer.Relay.NodeID == change.ID {
				return m, nil, refused
			}
		}
	}
	next.ProtocolSecrets = maps.Clone(m.ProtocolSecrets)
	next.HysteriaSecrets = maps.Clone(m.HysteriaSecrets)
	next.TrafficCounters = maps.Clone(m.TrafficCounters)
	next.DeletedRoutes = maps.Clone(m.DeletedRoutes)
	next.ManagedRouteLandings = maps.Clone(m.ManagedRouteLandings)
	accounts := slices.Clone(m.Plan.Accounts)
	removedRoutes := map[string]bool{}
	for i := range accounts {
		a := &accounts[i]
		a.Grants = slices.Clone(a.Grants)
		for _, grant := range a.Grants {
			if grant.EgressID != change.ID && grant.IPv4EgressID != change.ID && (!entry || grant.EntryID != change.ID) {
				continue
			}
			if grant.Enabled {
				return m, nil, refused
			}
			removedRoutes[grant.ID] = true
			delete(next.DeletedRoutes, grant.ID)
			delete(next.ManagedRouteLandings, grant.ID)
		}
		a.Grants = slices.DeleteFunc(a.Grants, func(g glivela.RouteGrant) bool { return removedRoutes[g.ID] })
		removedCredentials := map[string]bool{}
		a.Credentials = slices.Clone(a.Credentials)
		for _, c := range a.Credentials {
			if c.EgressID != change.ID && (!entry || c.EntryID != change.ID) {
				continue
			}
			if c.Kind != glivela.RouteCredential && (!entry || c.EntryID != change.ID) {
				return m, nil, refused
			}
			// A composite route's other exit cannot be silently changed.
			for _, grant := range a.Grants {
				if grant.Route.ID == c.ID || grant.Base.ID == c.ID {
					return m, nil, refused
				}
			}
			removedCredentials[c.ID] = true
			if entry {
				removed[c.ID] = true
			}
			delete(next.ProtocolSecrets, c.ID)
			delete(next.HysteriaSecrets, c.ID)
			delete(next.TrafficCounters, c.ID)
		}
		a.HysteriaIdentities = maps.Clone(a.HysteriaIdentities)
		for id := range removedCredentials {
			delete(a.HysteriaIdentities, id)
		}
		a.Credentials = slices.DeleteFunc(a.Credentials, func(c glivela.Credential) bool { return removedCredentials[c.ID] })
		a.Usage = slices.Clone(a.Usage)
		for _, u := range a.Usage {
			if !removedCredentials[u.CredentialID] {
				continue
			}
			amount := u.Observed - u.Baseline
			if amount < 0 || a.RetiredUsageBytes > math.MaxInt64-amount {
				return m, nil, errors.New("control: retired usage overflow")
			}
			a.RetiredUsageBytes += amount
		}
		a.Usage = slices.DeleteFunc(a.Usage, func(u glivela.UsageMember) bool { return removedCredentials[u.CredentialID] })
	}
	var err error
	next.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		return m, nil, err
	}
	next.ClientChains = make([]glivela.ClientChain, 0, len(m.ClientChains))
	next.DeletedClientChains = maps.Clone(m.DeletedClientChains)
	for _, chain := range m.ClientChains {
		if chain.EntryID == change.ID || chain.EgressID == change.ID || chain.Relay != nil && chain.Relay.NodeID == change.ID {
			if chain.Enabled {
				return m, nil, refused
			}
			removed[chain.ID] = true
			delete(next.DeletedClientChains, chain.ID)
		} else {
			next.ClientChains = append(next.ClientChains, chain)
		}
	}
	next.ClientLandings = maps.Clone(m.ClientLandings)
	// A removed three-hop chain may have been the last reference to another
	// shared landing. Remove its now-unused chain key, never its node enrollment.
	for id := range next.ClientLandings {
		if !slices.ContainsFunc(next.ClientChains, func(c glivela.ClientChain) bool { return c.EgressID == id && !next.DeletedClientChains[c.ID] }) {
			delete(next.ClientLandings, id)
		}
	}
	next.SubscriptionOrders = maps.Clone(m.SubscriptionOrders)
	for id, order := range next.SubscriptionOrders {
		ids := slices.DeleteFunc(slices.Clone(order.IDs), func(id string) bool {
			parts := strings.Split(id, "/")
			if entry && len(parts) == 3 && parts[0] == "native" && removed[parts[2]] {
				return true
			}
			return removed[strings.TrimPrefix(id, "chain/")] && strings.HasPrefix(id, "chain/") || removedRoutes[strings.TrimPrefix(id, "route/")] && strings.HasPrefix(id, "route/")
		})
		if len(ids) != len(order.IDs) {
			if order.Revision == math.MaxUint64 {
				return m, nil, errors.New("control: subscription revision exhausted")
			}
			order.IDs = ids
			order.Revision++
			next.SubscriptionOrders[id] = order
		}
	}
	next.References.Nodes = maps.Clone(m.References.Nodes)
	next.References.Applications = maps.Clone(m.References.Applications)
	next.References.Services = maps.Clone(m.References.Services)
	next.References.Publications = maps.Clone(m.References.Publications)
	delete(next.References.Nodes, change.ID)
	if change.hostID != "" {
		delete(next.References.Nodes, change.hostID)
	}
	apps, services := map[string]bool{}, map[string]bool{}
	for id, app := range next.References.Applications {
		if app.NodeID == change.ID || entry && id == change.ID || change.hostID != "" && app.NodeID == change.hostID {
			apps[id] = true
			delete(next.References.Applications, id)
		}
	}
	for id, service := range next.References.Services {
		if apps[service.ApplicationID] {
			services[id] = true
			delete(next.References.Services, id)
		}
	}
	for id, publication := range next.References.Publications {
		if publication.EntryNodeID == change.ID || change.hostID != "" && publication.EntryNodeID == change.hostID || services[publication.ServiceID] {
			// A shared publication requires its own explicit retirement scope.
			if (publication.EntryNodeID != change.ID && publication.EntryNodeID != change.hostID) || !services[publication.ServiceID] {
				return m, nil, errors.New("control: landing has a shared publication")
			}
			delete(next.References.Publications, id)
		}
	}
	if selection := m.References.LandingSelection; selection != nil {
		copy := *selection
		copy.NodeIDs = slices.DeleteFunc(slices.Clone(selection.NodeIDs), func(id string) bool { return id == change.ID })
		copy.RetiringNodeIDs = slices.DeleteFunc(slices.Clone(selection.RetiringNodeIDs), func(id string) bool { return id == change.ID })
		copy.LandingRegionCodes = maps.Clone(selection.LandingRegionCodes)
		delete(copy.LandingRegionCodes, change.ID)
		copy.LandingNameSuffixes = maps.Clone(selection.LandingNameSuffixes)
		delete(copy.LandingNameSuffixes, change.ID)
		if !reflect.DeepEqual(copy, *selection) {
			if copy.Revision == math.MaxUint64 {
				return m, nil, errors.New("control: landing selection revision exhausted")
			}
			copy.Revision++
		}
		next.References.LandingSelection = &copy
	}
	next.RetiredLandings = maps.Clone(m.RetiredLandings)
	if next.RetiredLandings == nil {
		next.RetiredLandings = map[string]glivela.RetiredLanding{}
	}
	hostID := change.hostID
	if !entry || hostID == change.ID {
		hostID = ""
	}
	next.RetiredLandings[change.ID] = glivela.RetiredLanding{HostID: hostID, CertificateID: change.CertificateID, Revision: change.ExpectedRevision}
	return next, removed, next.Validate()
}

func projectRetiredLandings(nodes map[string]Node, m glivela.ImportMaterial) (map[string]Node, bool, error) {
	next := maps.Clone(nodes)
	changed := false
	for cert, node := range nodes {
		if _, retired := m.RetiredLandings[node.ID]; retired {
			delete(next, cert)
			changed = true
			continue
		}
		if node.Desired.Landing != nil {
			entries := maps.Clone(node.RouteEntries)
			addresses := map[string]bool{}
			for id, member := range entries {
				if retired, ok := m.RetiredLandings[id]; ok {
					if retired.CertificateID != member.CertificateID {
						return nil, false, errors.New("control: retired source identity changed")
					}
					addresses[member.Address] = true
					delete(entries, id)
				}
			}
			if len(addresses) > 0 {
				if node.TransportTail != nil || node.TransportPrevious != nil || node.Desired.Revision == math.MaxUint64 {
					return nil, false, errors.New("control: landing source transition pending")
				}
				plan := *node.Desired.Landing
				plan.Sources = slices.DeleteFunc(slices.Clone(plan.Sources), func(v landing.Source) bool { return addresses[v.Address] })
				if len(plan.Sources) == 0 {
					plan.Transport = glivela.PrivateTransport{}
				}
				plan.Revision++
				desired, err := newLandingDesiredVersion(plan, node.Desired.LandingRenderVersion)
				if err != nil {
					return nil, false, err
				}
				node.Desired, node.RouteEntries = desired, entries
				node.Receipt, node.Checks, node.ReportedAt = nil, nil, time.Time{}
				next[cert] = node
				changed = true
			}
			continue
		}
		if node.Desired.Entry == nil {
			continue
		}
		desired := node.Desired.clone()
		retired := func(id string) bool { _, ok := m.RetiredLandings[id]; return ok }
		desired.Entry.Credentials = slices.DeleteFunc(desired.Entry.Credentials, func(c glivela.CredentialMaterial) bool { return retired(c.Credential.EgressID) })
		desired.Entry.Grants = slices.DeleteFunc(desired.Entry.Grants, func(g glivela.RouteGrant) bool { return retired(g.EgressID) || retired(g.IPv4EgressID) })
		desired.Entry.Peers = slices.DeleteFunc(desired.Entry.Peers, func(p glivela.RoutePeer) bool { return retired(p.EgressID) })
		desired.EntryNetwork.Peers = slices.DeleteFunc(desired.EntryNetwork.Peers, func(p EntryPeer) bool { return retired(p.EgressID) })
		desired.EntryNetwork.SpeedPeers = slices.DeleteFunc(desired.EntryNetwork.SpeedPeers, func(p EntrySpeedPeer) bool { return retired(p.LandingID) })
		if len(desired.EntryNetwork.Peers) == 0 {
			desired.EntryNetwork.Source = nil
		}
		if reflect.DeepEqual(desired.Entry, node.Desired.Entry) && reflect.DeepEqual(desired.EntryNetwork, node.Desired.EntryNetwork) {
			continue
		}
		if node.TransportTail != nil || desired.Entry.Revision == math.MaxUint64 {
			return nil, false, errors.New("control: entry transport change is pending")
		}
		desired.Entry.Revision++
		updated, err := newEntryDesiredVersion(*desired.Entry, *desired.EntryNetwork, desired.EntryRenderVersion)
		if err != nil {
			return nil, false, err
		}
		node.Desired, node.Receipt, node.ReportedAt, node.EntryHealthBarrierAt = updated, nil, time.Time{}, time.Time{}
		node.TransportPrevious = nil
		next[cert] = node
		changed = true
		invalidateEntryChecks(next, node.ID)
	}
	return next, changed, nil
}

func (s *Store) cleanLandingPresentationLocked(id string, chains map[string]bool) error {
	directory := filepath.Dir(s.path)
	current, err := loadSubscriptionPresentation(directory, s.business.material)
	if err != nil || !reflect.DeepEqual(current.Names, s.subscriptionNames) || !reflect.DeepEqual(current.Landings, s.subscriptionLandings) {
		return errors.New("control: subscription presentation changed")
	}
	current.Names = maps.Clone(current.Names)
	current.Landings = maps.Clone(current.Landings)
	for chain := range chains {
		delete(current.Names, chain)
	}
	delete(current.Landings, id)
	if !reflect.DeepEqual(current.Names, s.subscriptionNames) || !reflect.DeepEqual(current.Landings, s.subscriptionLandings) {
		if len(current.Names)+len(current.Landings) == 0 {
			if err := os.Remove(filepath.Join(directory, subscriptionNamesFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := syncBusinessDirectory(directory); err != nil {
				return err
			}
		} else if err := writeControlState(filepath.Join(directory, subscriptionNamesFile), current); err != nil {
			return err
		}
		s.subscriptionNames, s.subscriptionLandings = current.Names, current.Landings
	}
	if _, ok := s.hostBindings[id]; ok {
		var current hostBindingState
		if err := readControlState(filepath.Join(directory, hostBindingsFile), &current); err != nil {
			return err
		}
		if current.validate() != nil || !reflect.DeepEqual(current.Bindings, s.hostBindings) {
			return errors.New("control: host bindings changed")
		}
		current.Bindings = maps.Clone(current.Bindings)
		delete(current.Bindings, id)
		if err := writeControlState(filepath.Join(directory, hostBindingsFile), current); err != nil {
			return err
		}
		s.hostBindings = current.Bindings
	}
	return nil
}

func (s *Store) cleanLandingHistoryLocked(id string) error {
	history, err := s.qualityLocked()
	if err != nil {
		return err
	}
	before := len(history.Checks)
	history.Checks = slices.DeleteFunc(history.Checks, func(c QualityCheck) bool { return c.NodeID == id })
	if len(history.Checks) != before {
		if err := s.saveQualityLocked(history); err != nil {
			return err
		}
	}
	s.loadLatencyHistoryLocked()
	if s.latencyHistoryFault {
		return errors.New("control: latency history unavailable")
	}
	next := latencyHistoryState{Version: 1, Targets: maps.Clone(s.latencyHistory.Targets)}
	for key := range next.Targets {
		parts := strings.Split(key, "/")
		if parts[0] == id || parts[1] == id {
			delete(next.Targets, key)
		}
	}
	if len(next.Targets) != len(s.latencyHistory.Targets) {
		if err := writeControlState(filepath.Join(filepath.Dir(s.path), "route-latency-history.json"), next); err != nil {
			return err
		}
		s.latencyHistory = &next
	}
	jobs := maps.Clone(s.speedJobs)
	for key, job := range jobs {
		if job.Request.EntryID == id || job.Request.LandingID == id {
			delete(jobs, key)
		}
	}
	if len(jobs) != len(s.speedJobs) {
		previous := s.speedJobs
		s.speedJobs = jobs
		if err := s.saveSpeedLocked(); err != nil {
			s.speedJobs = previous
			return err
		}
	}
	for key, record := range s.latencies {
		if record.Target.EntryID == id || record.Target.LandingID == id {
			delete(s.latencies, key)
		}
	}
	// Volatile diagnostics are keyed by the runtime certificate, not host ID.
	certificate := s.business.material.RetiredLandings[id].CertificateID
	delete(s.qualityPolls, certificate)
	delete(s.networkReports, certificate)
	delete(s.pathMTUNodes, certificate)
	delete(s.pathMTUReports, certificate)
	return nil
}
