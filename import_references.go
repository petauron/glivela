package glivela

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode/utf8"
)

// ImportReferences preserves object identities and display/publication data.
// PreviousStatus and saved network observations are not current reachability
// or write authority. No platform credentials/capability matrix are imported.
type ImportReferences struct {
	Nodes            map[string]ImportNode        `json:"nodes"`
	Applications     map[string]ImportApplication `json:"applications"`
	Services         map[string]ImportService     `json:"services"`
	Publications     map[string]ImportPublication `json:"publications"`
	LandingSelection *ImportLandingSelection      `json:"landingSelection,omitempty"`
}
type ImportNode struct {
	Name                string          `json:"name"`
	PreviousStatus      string          `json:"previousStatus"`
	ServiceAddress      string          `json:"serviceAddress"`
	PrivateAddress      string          `json:"privateAddress"`
	PeerJSON            json.RawMessage `json:"peer,omitempty"`
	EgressAddressesJSON json.RawMessage `json:"egressAddresses,omitempty"`
}
type ImportApplication struct {
	Name           string `json:"name"`
	NodeID         string `json:"nodeId"`
	Runtime        string `json:"runtime"`
	PreviousStatus string `json:"previousStatus"`
}
type ImportService struct {
	Timezone            string `json:"timezone"`
	ApplicationID       string `json:"applicationId"`
	Name                string `json:"name"`
	DisplayName         string `json:"displayName"`
	RegionCode          string `json:"regionCode"`
	Protocol            string `json:"protocol"`
	ApplicationProtocol string `json:"applicationProtocol"`
	ContainerPort       int    `json:"containerPort"`
	HostPort            int    `json:"hostPort"`
	Endpoint            string `json:"endpoint"`
	PreviousStatus      string `json:"previousStatus"`
}
type ImportPublication struct {
	ServiceID           string `json:"serviceId"`
	EntryNodeID         string `json:"entryNodeId"`
	Kind                string `json:"kind"`
	IngressOwner        string `json:"ingressOwner"`
	Hostname            string `json:"hostname"`
	SNIHostname         string `json:"sniHostname"`
	DNSProvider         string `json:"dnsProvider"`
	DNSRecordID         string `json:"dnsRecordId"`
	AccessApplicationID string `json:"accessApplicationId"`
	TLSEnabled          bool   `json:"tlsEnabled"`
	DesiredRevision     uint64 `json:"desiredRevision"`
	AppliedRevision     uint64 `json:"appliedRevision"`
	PreviousStatus      string `json:"previousStatus"`
	PreviousError       string `json:"previousError"`
	ActionRequired      bool   `json:"actionRequired"`
	CleanupPending      bool   `json:"cleanupPending"`
	CleanupAttempt      int64  `json:"cleanupAttempt"`
	CleanupRetryAt      string `json:"cleanupRetryAt"`
	CreatedAt           string `json:"createdAt"`
	UpdatedAt           string `json:"updatedAt"`
}
type ImportLandingSelection struct {
	NodeIDs             []string          `json:"nodeIds"`
	LandingRegionCodes  map[string]string `json:"landingRegionCodes,omitempty"`
	LandingNameSuffixes map[string]string `json:"landingNameSuffixes,omitempty"`
	RetiringNodeIDs     []string          `json:"retiringNodeIds,omitempty"`
	Revision            uint64            `json:"revision"`
}

func (m ImportMaterial) validateReferences() error {
	r := m.References
	invalid := errors.New("glivela: incomplete or invalid imported references")
	text := func(s string, limit int) bool { return len(s) <= limit && !strings.ContainsAny(s, "\x00\r\n") }
	displayText := func(s string) bool {
		return utf8.RuneCountInString(s) <= MaxDisplayNameLength && !strings.ContainsAny(s, "\x00\r\n")
	}
	address := func(s string) bool {
		if s == "" {
			return true
		}
		a, err := netip.ParseAddr(s)
		return err == nil && a.Zone() == "" && a.String() == s
	}
	if len(r.Nodes) > 10000 || len(r.Applications) > 10000 || len(r.Services) > 10000 || len(r.Publications) > 10000 {
		return invalid
	}
	for id, n := range r.Nodes {
		if !ValidIdentifier(id) || !validDisplayName(n.Name) || n.PreviousStatus != "active" && n.PreviousStatus != "disabled" || !address(n.ServiceAddress) || !address(n.PrivateAddress) || len(n.PeerJSON) > 16<<10 || len(n.EgressAddressesJSON) > 64<<10 {
			return invalid
		}
		if len(n.PeerJSON) > 0 {
			var peer map[string]json.RawMessage
			if json.Unmarshal(n.PeerJSON, &peer) != nil {
				return invalid
			}
		}
		if len(n.EgressAddressesJSON) > 0 {
			var a []json.RawMessage
			// Legacy heartbeats marshal a nil observation slice as JSON null.
			// Keep that unknown observation distinct from an observed empty list;
			// neither is fresh evidence permitting an exit or network operation.
			if json.Unmarshal(n.EgressAddressesJSON, &a) != nil {
				return invalid
			}
		}
	}
	for id, a := range r.Applications {
		if _, ok := r.Nodes[a.NodeID]; !ok || !ValidIdentifier(id) || !validDisplayName(a.Name) || !text(a.Runtime, 32) || !text(a.PreviousStatus, 32) {
			return invalid
		}
	}
	for id, s := range r.Services {
		if s.Timezone != "" {
			if _, err := time.LoadLocation(s.Timezone); err != nil || len(s.Timezone) > 128 {
				return invalid
			}
		}
		if _, ok := r.Applications[s.ApplicationID]; !ok || !ValidIdentifier(id) || !displayText(s.Name) || !displayText(s.DisplayName) || !text(s.RegionCode, 16) || !text(s.ApplicationProtocol, 128) || !text(s.Endpoint, 1024) || s.ContainerPort < 0 || s.ContainerPort > 65535 || s.HostPort < 0 || s.HostPort > 65535 {
			return invalid
		}
		switch s.Protocol {
		case "tcp", "udp", "http", "https":
		default:
			return invalid
		}
	}
	for id, p := range r.Publications {
		_, service := r.Services[p.ServiceID]
		_, node := r.Nodes[p.EntryNodeID]
		if !ValidIdentifier(id) || !service || !node || !text(p.Hostname, 253) || !text(p.SNIHostname, 253) || !text(p.DNSRecordID, 512) || !text(p.AccessApplicationID, 512) || p.DesiredRevision == 0 || p.AppliedRevision > p.DesiredRevision || p.CleanupAttempt < 0 || len(p.PreviousError) > 64<<10 || !validImportTime(p.CleanupRetryAt) || p.CreatedAt == "" || p.UpdatedAt == "" || !validImportTime(p.CreatedAt) || !validImportTime(p.UpdatedAt) {
			return invalid
		}
		switch p.DNSProvider {
		case "manual", "cloudflare", "headscale":
		default:
			return invalid
		}
		validOwner := p.IngressOwner == "site_gateway" && (p.Kind == "lan_gateway" || p.Kind == "headscale_gateway" || p.Kind == "public_direct") || p.IngressOwner == "application_node" && (p.Kind == "public_direct" || p.Kind == "public_shared_443") || p.IngressOwner == "tunnel_connector" && p.Kind == "cloudflare_tunnel"
		if !validOwner {
			return invalid
		}
	}
	for _, e := range m.Endpoints {
		s, ok := r.Services[e.ServiceID]
		if !ok || s.ApplicationID != e.Reality.EntryID {
			return invalid
		}
	}
	for _, a := range m.Plan.Accounts {
		for _, g := range a.Grants {
			if _, ok := r.Nodes[g.EgressID]; !ok {
				return invalid
			}
			if g.IPv4EgressID != "" {
				if _, ok := r.Nodes[g.IPv4EgressID]; !ok {
					return invalid
				}
			}
		}
	}
	if s := r.LandingSelection; s != nil {
		if s.Revision == 0 || s.NodeIDs == nil || len(s.NodeIDs)+len(s.RetiringNodeIDs) > 10000 {
			return invalid
		}
		seen := map[string]bool{}
		for _, ids := range [][]string{s.NodeIDs, s.RetiringNodeIDs} {
			for _, id := range ids {
				if _, ok := r.Nodes[id]; !ok || seen[id] {
					return invalid
				}
				seen[id] = true
			}
		}
		for id, region := range s.LandingRegionCodes {
			if !seen[id] || !text(region, 16) {
				return invalid
			}
		}
		for id, name := range s.LandingNameSuffixes {
			if !seen[id] || !displayText(name) {
				return invalid
			}
		}
	}
	return nil
}
