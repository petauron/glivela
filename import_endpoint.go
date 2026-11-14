package glivela

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"time"
)

// ImportEndpoint retains the existing proxy configuration and historical
// observations. None of PreviousStatus, AppliedRevision or HistoricalHealthy
// is fresh runtime evidence for the newly enrolled controller.
type ImportEndpoint struct {
	// PreviousAdvertiseHost authorizes recovery of the latest metadata-only
	// subscription address change, without accepting unrelated runtime drift.
	PreviousAdvertiseHost string                `json:"previousAdvertiseHost,omitempty"`
	PreviousPublicIngress *RealityPublicIngress `json:"previousPublicIngress,omitempty"`

	RealityChanges       []RealityTargetChange `json:"realityChanges,omitempty"`
	Reality              RealityEndpoint       `json:"reality"`
	Hysteria             *HysteriaEndpoint     `json:"hysteria,omitempty"`
	ServiceID            string                `json:"serviceId"`
	RuntimeCertificateID string                `json:"runtimeCertificateId,omitempty"`
	RuntimeConfigSHA256  string                `json:"runtimeConfigSha256,omitempty"`
	TargetIP             string                `json:"targetIp"`
	VLESSEnabled         bool                  `json:"vlessEnabled"`
	HysteriaEnabled      bool                  `json:"hysteriaEnabled"`
	TotalBytes           int64                 `json:"totalBytes"`
	UsedBytes            int64                 `json:"usedBytes"`
	QuotaAppliedEnabled  bool                  `json:"quotaAppliedEnabled"`
	ResetDay             int                   `json:"resetDay"`
	ResetSchedule        ImportResetSchedule   `json:"resetSchedule"`
	DesiredRevision      uint64                `json:"desiredRevision"`
	AppliedRevision      uint64                `json:"appliedRevision"`
	HistoricalHealthy    bool                  `json:"historicalHealthy"`
	PreviousStatus       string                `json:"previousStatus"`
	PreviousError        string                `json:"previousError"`
	LegacyRetired        bool                  `json:"legacyRetired"`
	// Retired is the current endpoint policy. LegacyRetired above only
	// records retirement of the old implementation, not this endpoint.
	Retired             bool            `json:"retired"`
	SourcePeerJSON      json.RawMessage `json:"sourcePeer"`
	CertificateNotAfter string          `json:"certificateNotAfter"`
	CreatedAt           string          `json:"createdAt"`
	UpdatedAt           string          `json:"updatedAt"`
}

// RealityPublicIngress is the exact previous socket tuple for forward recovery;
// it contains no credentials, target, account or traffic snapshot.
type RealityPublicIngress struct {
	ListenPort        int    `json:"listenPort"`
	AdvertisePort     int    `json:"advertisePort"`
	IPv4ListenAddress string `json:"ipv4ListenAddress,omitempty"`
}

func (e ImportEndpoint) Validate() error {
	if p := e.PreviousPublicIngress; p != nil {
		previous := e.Reality
		previous.ListenPort = p.ListenPort
		previous.AdvertisePort = p.AdvertisePort
		previous.IPv4ListenAddress = p.IPv4ListenAddress
		if previous.Validate() != nil {
			return errors.New("glivela: invalid previous public listener")
		}
	}
	if e.PreviousAdvertiseHost != "" && (!validShareHost(e.PreviousAdvertiseHost) || e.PreviousAdvertiseHost == e.Reality.AdvertiseHost) {
		return errors.New("glivela: invalid previous subscription host")
	}
	if len(e.RealityChanges) > 32 {
		return errors.New("glivela: REALITY change history limit")
	}
	for i, c := range e.RealityChanges {
		if proof := c.InitialRepair; proof != nil {
			host, port, err := net.SplitHostPort(c.PreviousTarget)
			verified, timeErr := time.Parse(time.RFC3339Nano, proof.VerifiedAt)
			changed, changeErr := time.Parse(time.RFC3339Nano, c.ChangedAt)
			if i != 0 || err != nil || port == "24483" || c.PreviousTargetIP != "127.0.0.1" || len(c.PreviousServerNames) != 1 || c.PreviousServerNames[0] != host || c.ServerName != host || c.Target != net.JoinHostPort(host, "24483") || c.TargetIP != "127.0.0.1" || c.State != "pending" && c.State != "accepted" || !ValidIdentity(proof.CertificateID) || !ValidIdentity(proof.ConfigSHA256) || !ValidIdentity(proof.EvidenceSHA256) || timeErr != nil || changeErr != nil || verified.After(changed) || changed.Sub(verified) > 15*time.Minute {
				return errors.New("glivela: invalid initial target repair evidence")
			}
		}
		if len(c.Reason) > 256 || (c.State == "reverting" || c.State == "reverted") && (c.Reason == "" || c.RevertedAt == "" || !validImportTime(c.RevertedAt)) {
			return errors.New("glivela: invalid target recovery record")
		}
		if !validRealityTarget(c.PreviousTarget) || !validRealityTarget(c.Target) || len(c.PreviousServerNames) == 0 || len(c.PreviousServerNames) > 16 || !validServerName(c.ServerName) || !validImportTime(c.ChangedAt) || c.ChangedAt == "" {
			return errors.New("glivela: invalid REALITY change history")
		}
		for _, n := range c.PreviousServerNames {
			if !validServerName(n) {
				return errors.New("glivela: invalid previous SNI")
			}
		}
		ip, err := netip.ParseAddr(c.TargetIP)
		if err != nil || !ValidRealityTargetPin(c.Target, c.TargetIP) {
			return errors.New("glivela: invalid target pin")
		}
		if c.PreviousTargetIP != "" {
			ip, err = netip.ParseAddr(c.PreviousTargetIP)
			if err != nil || ip.String() != c.PreviousTargetIP {
				return errors.New("glivela: invalid previous target pin")
			}
		}
		switch c.State {
		case "pending", "reverting":
			if c.EvidenceSHA256 != "" || c.VerifiedAt != "" {
				return errors.New("glivela: unaccepted target evidence")
			}
		case "accepted", "reverted":
			if !ValidIdentity(c.EvidenceSHA256) || c.VerifiedAt == "" || !validImportTime(c.VerifiedAt) {
				return errors.New("glivela: invalid target acceptance")
			}
		default:
			return errors.New("glivela: invalid target change state")
		}
	}

	// The reviewed schema-113 CHECK(vless_enabled=1 OR hy2_enabled=1)
	// applies to every row, including retired endpoints. Retiring an endpoint
	// changes its status, not these saved protocol configuration flags.
	address, err := netip.ParseAddr(e.TargetIP)
	if e.Reality.Validate() != nil || !ValidIdentifier(e.ServiceID) || e.TargetIP != "" && (err != nil || address.String() != e.TargetIP || address.Zone() != "") || !e.VLESSEnabled && !e.HysteriaEnabled || e.TotalBytes < 0 || e.UsedBytes < 0 || e.ResetDay < 0 || e.ResetDay > 31 || e.DesiredRevision == 0 || e.AppliedRevision > e.DesiredRevision || len(e.PreviousError) > 64<<10 {
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
	var source struct {
		Schema int `json:"sourceSchema"`
	}
	if json.Unmarshal(material.RetainedSource, &source) != nil {
		return errors.New("glivela: invalid endpoint source")
	}
	byEntry := map[string]ImportEndpoint{}
	ids, services := map[string]bool{}, map[string]bool{}
	for _, endpoint := range endpoints {
		// Native schema-120 entries retain their configured DNS target. Legacy
		// imports must still retain the previously reviewed fixed target IP.
		if endpoint.TargetIP == "" && (source.Schema != 120 && (material.Ownership == nil || material.Ownership.Origin != "native") || material.References.Applications[endpoint.Reality.EntryID].Runtime != "host" && !ValidIdentity(endpoint.RuntimeCertificateID)) {
			return errors.New("glivela: missing imported target pin")
		}
		if (endpoint.RuntimeCertificateID != "" || endpoint.RuntimeConfigSHA256 != "") && (!ValidIdentity(endpoint.RuntimeCertificateID) || !ValidIdentity(endpoint.RuntimeConfigSHA256)) {
			return errors.New("glivela: invalid imported runtime binding")
		}
		if endpoint.ResetDay > 0 {
			zone := material.References.Services[endpoint.ServiceID].Timezone
			if zone == "" {
				return errors.New("glivela: endpoint reset timezone required")
			}
			if _, err := time.LoadLocation(zone); err != nil {
				return errors.New("glivela: invalid endpoint reset timezone")
			}
		}
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
			if !ok {
				if _, archived := material.PrunedEntries[credential.EntryID]; archived {
					continue
				}
			}
			if !ok || account.HysteriaIdentities[credential.ID] != "" && endpoint.Hysteria == nil {
				return errors.New("glivela: missing credential endpoint")
			}
		}
		for _, grant := range account.Grants {
			endpoint, ok := byEntry[grant.EntryID]
			if !ok {
				if archived, found := material.PrunedEntries[grant.EntryID]; found && !grant.Enabled && grant.InboundTag == archived.InboundTag {
					continue
				}
			}
			if !ok || grant.InboundTag != endpoint.Reality.InboundTag {
				return errors.New("glivela: changed route endpoint")
			}
		}
	}
	return nil
}

// RealityInitialRepair records an administrator attestation, not a node receipt
// or public-client acceptance. The full evidence stays outside business state.
type RealityInitialRepair struct {
	CertificateID  string `json:"certificateId"`
	ConfigSHA256   string `json:"configSha256"`
	EvidenceSHA256 string `json:"evidenceSha256"`
	VerifiedAt     string `json:"verifiedAt"`
}

// RealityTargetChange retains only fields needed for forward recovery. It never
// snapshots account secrets, quotas or traffic ledgers.
type RealityTargetChange struct {
	InitialRepair       *RealityInitialRepair `json:"initialRepair,omitempty"`
	RevertedAt          string                `json:"revertedAt,omitempty"`
	Reason              string                `json:"reason,omitempty"`
	PreviousTarget      string                `json:"previousTarget"`
	PreviousTargetIP    string                `json:"previousTargetIp"`
	PreviousServerNames []string              `json:"previousServerNames"`
	Target              string                `json:"target"`
	TargetIP            string                `json:"targetIp"`
	ServerName          string                `json:"serverName"`
	State               string                `json:"state"`
	ChangedAt           string                `json:"changedAt"`
	EvidenceSHA256      string                `json:"evidenceSha256,omitempty"`
	VerifiedAt          string                `json:"verifiedAt,omitempty"`
}
