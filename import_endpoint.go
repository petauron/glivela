package glivela

import (
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

// ImportEndpoint retains the existing proxy configuration and historical
// observations. None of PreviousStatus, AppliedRevision or HistoricalHealthy
// is fresh runtime evidence for the newly enrolled controller.
type ImportEndpoint struct {
	Reality             RealityEndpoint     `json:"reality"`
	Hysteria            *HysteriaEndpoint   `json:"hysteria,omitempty"`
	ServiceID           string              `json:"serviceId"`
	TargetIP            string              `json:"targetIp"`
	VLESSEnabled        bool                `json:"vlessEnabled"`
	HysteriaEnabled     bool                `json:"hysteriaEnabled"`
	TotalBytes          int64               `json:"totalBytes"`
	UsedBytes           int64               `json:"usedBytes"`
	QuotaAppliedEnabled bool                `json:"quotaAppliedEnabled"`
	ResetDay            int                 `json:"resetDay"`
	ResetSchedule       ImportResetSchedule `json:"resetSchedule"`
	DesiredRevision     uint64              `json:"desiredRevision"`
	AppliedRevision     uint64              `json:"appliedRevision"`
	HistoricalHealthy   bool                `json:"historicalHealthy"`
	PreviousStatus      string              `json:"previousStatus"`
	PreviousError       string              `json:"previousError"`
	LegacyRetired       bool                `json:"legacyRetired"`
	// Retired is the current endpoint policy. LegacyRetired above only
	// records retirement of the old implementation, not this endpoint.
	Retired             bool            `json:"retired"`
	SourcePeerJSON      json.RawMessage `json:"sourcePeer"`
	CertificateNotAfter string          `json:"certificateNotAfter"`
	CreatedAt           string          `json:"createdAt"`
	UpdatedAt           string          `json:"updatedAt"`
}

func (e ImportEndpoint) Validate() error {
	// The reviewed schema-113 CHECK(vless_enabled=1 OR hy2_enabled=1)
	// applies to every row, including retired endpoints. Retiring an endpoint
	// changes its status, not these saved protocol configuration flags.
	address, err := netip.ParseAddr(e.TargetIP)
	if e.Reality.Validate() != nil || !ValidIdentifier(e.ServiceID) || err != nil || address.String() != e.TargetIP || address.Zone() != "" || !e.VLESSEnabled && !e.HysteriaEnabled || e.TotalBytes < 0 || e.UsedBytes < 0 || e.ResetDay < 0 || e.ResetDay > 31 || e.DesiredRevision == 0 || e.AppliedRevision > e.DesiredRevision || len(e.PreviousError) > 64<<10 {
		return errors.New("glivela: invalid imported endpoint")
	}
	switch e.PreviousStatus {
	case "importing", "pending", "applying", "ready", "failed", "retired":
	default:
		return errors.New("glivela: invalid historical endpoint status")
	}
	if !validImportTime(e.ResetSchedule.NextResetAt) || !validImportTime(e.ResetSchedule.LastResetAt) || e.CreatedAt == "" || e.UpdatedAt == "" || !validImportTime(e.CreatedAt) || !validImportTime(e.UpdatedAt) || len(e.SourcePeerJSON) > 16<<10 {
		return errors.New("glivela: invalid imported endpoint metadata")
	}
	var peer map[string]json.RawMessage
	if json.Unmarshal(e.SourcePeerJSON, &peer) != nil || peer == nil {
		return errors.New("glivela: invalid historical peer data")
	}
	if e.Hysteria == nil {
		if e.HysteriaEnabled || e.CertificateNotAfter != "" {
			return errors.New("glivela: missing imported Hysteria configuration")
		}
		return nil
	}
	h := e.Hysteria
	if h.ID != e.Reality.ID+"-hy2" || h.EntryID != e.Reality.EntryID || h.AdvertiseHost != e.Reality.AdvertiseHost || h.Validate() != nil {
		return errors.New("glivela: changed imported Hysteria identity")
	}
	actual, err := HysteriaCertificateNotAfter(*h)
	recorded, timeErr := time.Parse(time.RFC3339Nano, e.CertificateNotAfter)
	if err != nil || timeErr != nil || !actual.Equal(recorded) {
		return errors.New("glivela: changed imported certificate expiry")
	}
	return nil
}

// ValidateEndpointImport covers every credential's existing entry, not just
// entries selected for the first landing migration. Empty account inventories
// may legitimately coexist with configured endpoints and vice versa.
func ValidateEndpointImport(material ImportMaterial, endpoints []ImportEndpoint) error {
	material.Endpoints = endpoints
	return material.Validate()
}

func (material ImportMaterial) validateEndpoints() error {
	endpoints := material.Endpoints
	if len(endpoints) > 10000 {
		return errors.New("glivela: invalid endpoint inventory")
	}
	byEntry := map[string]ImportEndpoint{}
	ids, services := map[string]bool{}, map[string]bool{}
	for _, endpoint := range endpoints {
		if endpoint.Validate() != nil || ids[endpoint.Reality.ID] || services[endpoint.ServiceID] {
			return errors.New("glivela: conflicting endpoint inventory")
		}
		if _, duplicate := byEntry[endpoint.Reality.EntryID]; duplicate {
			return errors.New("glivela: conflicting entry identity")
		}
		ids[endpoint.Reality.ID], services[endpoint.ServiceID] = true, true
		byEntry[endpoint.Reality.EntryID] = endpoint
	}
	for _, account := range material.Plan.Accounts {
		for _, credential := range account.Credentials {
			endpoint, ok := byEntry[credential.EntryID]
			if !ok || account.HysteriaIdentities[credential.ID] != "" && endpoint.Hysteria == nil {
				return errors.New("glivela: missing credential endpoint")
			}
		}
		for _, grant := range account.Grants {
			endpoint, ok := byEntry[grant.EntryID]
			if !ok || grant.InboundTag != endpoint.Reality.InboundTag {
				return errors.New("glivela: changed route endpoint")
			}
		}
	}
	return nil
}
