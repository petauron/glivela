package glivela

import "errors"

// PrunedEntry is a non-executable accounting identity and certificate revocation
// fence. It contains no hostname, listener, TLS key or deployment configuration.
// Historical credentials, watermarks and the original source archive stay intact.
type PrunedEntry struct {
	CertificateID string              `json:"certificateId"`
	Revision      uint64              `json:"revision,string"`
	EndpointID    string              `json:"endpointId"`
	ServiceID     string              `json:"serviceId"`
	InboundTag    string              `json:"inboundTag"`
	TotalBytes    int64               `json:"totalBytes"`
	UsedBytes     int64               `json:"usedBytes"`
	ResetDay      int                 `json:"resetDay"`
	ResetSchedule ImportResetSchedule `json:"resetSchedule"`
	CreatedAt     string              `json:"createdAt"`
	UpdatedAt     string              `json:"updatedAt"`
}

func (m ImportMaterial) validatePrunedEntries() error {
	bad := errors.New("glivela: invalid pruned entry or active dependency")
	if len(m.PrunedEntries) > 10000 || len(m.PrunedEntries) > 0 && (m.Ownership == nil || m.ServerTransportVersion != 1) {
		return bad
	}
	certificates, endpoints, services := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for id, entry := range m.PrunedEntries {
		service, found := m.References.Services[entry.ServiceID]
		if !ValidIdentifier(id) || !ValidIdentifier(entry.EndpointID) || !ValidIdentifier(entry.ServiceID) || !validInboundTag(entry.InboundTag) || !ValidIdentity(entry.CertificateID) || entry.Revision == 0 || !found || service.ApplicationID != id || entry.TotalBytes < 0 || entry.UsedBytes < 0 || entry.ResetDay < 0 || entry.ResetDay > 31 || entry.CreatedAt == "" || entry.UpdatedAt == "" || !validImportTime(entry.CreatedAt) || !validImportTime(entry.UpdatedAt) || !validImportTime(entry.ResetSchedule.NextResetAt) || !validImportTime(entry.ResetSchedule.LastResetAt) || certificates[entry.CertificateID] || endpoints[entry.EndpointID] || services[entry.ServiceID] {
			return bad
		}
		certificates[entry.CertificateID], endpoints[entry.EndpointID], services[entry.ServiceID] = true, true, true
		if _, landing := m.RetiredLandings[id]; landing {
			return bad
		}
		if _, shared := m.ClientLandings[id]; shared {
			return bad
		}
		for _, endpoint := range m.Endpoints {
			if endpoint.Reality.EntryID == id || endpoint.Reality.ID == entry.EndpointID || endpoint.ServiceID == entry.ServiceID || endpoint.RuntimeCertificateID == entry.CertificateID {
				return bad
			}
		}
		for _, resource := range m.ServerTransports {
			if resource.EntryID == id || resource.EgressID == id || resource.EntryCertificateID == entry.CertificateID || resource.LandingCertificateID == entry.CertificateID || resource.Peer.Relay != nil && (resource.Peer.Relay.NodeID == id || resource.Peer.Relay.CertificateID == entry.CertificateID) {
				return bad
			}
		}
		for _, chain := range m.ClientChains {
			if chain.EntryID == id || chain.EgressID == id || chain.Relay != nil && chain.Relay.NodeID == id {
				return bad
			}
		}
		for _, account := range m.Plan.Accounts {
			for _, credential := range account.Credentials {
				if credential.EntryID != id && credential.EgressID == id {
					return bad
				}
			}
			for _, grant := range account.Grants {
				if grant.EntryID == id && (grant.Enabled || grant.InboundTag != entry.InboundTag) || grant.EgressID == id || grant.IPv4EgressID == id {
					return bad
				}
			}
		}
	}
	return nil
}
