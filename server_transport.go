package glivela

import (
	"errors"
	"net/netip"
	"strings"
)

// TransportListener is an exact-source SS2022 socket policy. Publication mode
// does not own this wire contract; both server and client policies render it.
type TransportListener struct {
	Interface string `json:"interface,omitempty"`
	EgressIP  string `json:"egressIp,omitempty"`
	Shared    bool   `json:"shared,omitempty"`
	Transport string `json:"transport,omitempty"`
	Address   string `json:"address,omitempty"`
	ID        string `json:"id"`
	Port      int    `json:"port"`
	Key       string `json:"key"`
	Source    string `json:"source"`
}

// ServerTransport owns a server route's already-enrolled transport. Its ID is
// a stable physical listener identity, not a reference to a client publication.
// Secrets live only in the authenticated encrypted business checkpoint.
type ServerTransport struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	AccountID            string             `json:"accountId"`
	EntryID              string             `json:"entryId"`
	EgressID             string             `json:"egressId"`
	EntryCertificateID   string             `json:"entryCertificateId"`
	LandingCertificateID string             `json:"landingCertificateId"`
	Peer                 RoutePeer          `json:"peer"`
	ExpectedExit         string             `json:"expectedExit"`
	Listener             TransportListener  `json:"listener"`
	RelayListener        *TransportListener `json:"relayListener,omitempty"`
}

func (r ServerTransport) Validate() error {
	bad := errors.New("glivela: invalid server transport resource")
	if !ValidIdentifier(r.ID) || !ValidIdentifier(r.AccountID) || !ValidIdentifier(r.EntryID) || !ValidIdentifier(r.EgressID) || r.EntryID == r.EgressID || r.ID == r.EntryID || r.ID == r.EgressID || !ValidIdentity(r.EntryCertificateID) || !ValidIdentity(r.LandingCertificateID) || r.EntryCertificateID == r.LandingCertificateID || r.Name == "" || len([]rune(r.Name)) > MaxDisplayNameLength || strings.TrimSpace(r.Name) != r.Name || strings.ContainsAny(r.Name, "\x00\r\n") || r.Peer.Validate() != nil || r.Peer.ExitFamily.Validate() != nil || r.Peer.EgressID != r.EgressID || r.Peer.Transport.ClientListenerID != r.ID || r.Listener.ID != r.ID || r.Listener.Port != r.Peer.Port || r.Listener.Key != r.Peer.Transport.Key {
		return bad
	}
	source, err := netip.ParseAddr(r.Listener.Source)
	if err != nil || source.String() != r.Listener.Source || source.IsUnspecified() || r.Listener.Source == r.Listener.Address || r.Listener.Transport != "ipv6-ss2022" && r.Listener.Transport != IPv4ClientSS2022 || (r.Peer.Relay == nil) != (r.RelayListener == nil) {
		return bad
	}
	if r.Peer.Transport.PrivateLink != nil {
		link := r.Peer.Transport.PrivateLink
		if r.Listener.Source != link.Source || r.Listener.Address != link.Address || r.Listener.Interface != link.Interface {
			return bad
		}
	} else if r.Listener.Interface != "" || r.Listener.Transport == "ipv6-ss2022" && r.Listener.Address != r.Peer.Transport.PublicAddress || r.Listener.Transport == IPv4ClientSS2022 && r.Listener.Address != "" {
		return bad
	}
	if r.RelayListener != nil {
		p, l := r.Peer.Relay, r.RelayListener
		if p.NodeID == r.EntryID || p.NodeID == r.EgressID || l.ID != r.ID || l.Port != p.Port || l.Key != p.Key || l.Shared || l.Interface != "" || l.EgressIP != "" {
			return bad
		}
		if p.Transport == IPv4RelaySS2022 {
			if l.Transport != IPv4RelaySS2022 || l.Source != p.SourceIPv4 || l.Address != "" {
				return bad
			}
		} else if l.Transport != "ipv6-ss2022" || l.Source != p.SourceIPv6 || l.Address != p.ServerIPv6 {
			return bad
		}
	}
	if r.ExpectedExit != "" {
		ip, e := netip.ParseAddr(r.ExpectedExit)
		if e != nil || ip.String() != r.ExpectedExit {
			return bad
		}
	}
	return nil
}
