package control

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
	pb "github.com/petauron/glivela/internal/controlpb"
	"github.com/petauron/glivela/landing"
)

// PublicPeerVerifier authenticates management identity, never proxy data or a
// replacement direct route. The actual public SS2022 probe remains mandatory.
type PublicPeerVerifier func(context.Context, Desired, EntryPeer) landing.LinkResult

type publicPeerProof struct {
	EntryID             string               `json:"entryId"`
	LandingID           string               `json:"landingId"`
	Revision            uint64               `json:"revision"`
	ConfigSHA256        string               `json:"configSha256"`
	Identity            landing.PeerIdentity `json:"identity"`
	LandingRevision     uint64               `json:"landingRevision"`
	LandingConfigSHA256 string               `json:"landingConfigSha256"`
	CheckedAt           time.Time            `json:"checkedAt"`
}

// This read-only proof uses the entry's existing mTLS identity and the landing's
// current mTLS receipt. It grants no host access, enrollment or configuration.
func (s *Store) publicPeerAcceptance(cert string, request landingAcceptanceRequest) (publicPeerProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publicPeerAcceptanceLocked(cert, request)
}

func (s *Store) publicPeerAcceptanceLocked(cert string, request landingAcceptanceRequest) (publicPeerProof, error) {
	refused := errors.New("control: public peer identity unavailable")
	entry, ok := s.nodes[cert]
	if !ok || entry.Desired.Entry == nil || entry.Desired.EntryNetwork == nil || entry.Desired.EntryNetwork.Source == nil ||
		request.SnapshotID != entry.ID || request.Revision != entry.Desired.Revision || request.ConfigSHA256 != entry.Desired.ConfigSHA256 || !glivela.ValidIdentifier(request.PeerID) || s.entryRetiredLocked(entry.ID) {
		return publicPeerProof{}, refused
	}
	pi := slices.IndexFunc(entry.Desired.EntryNetwork.Peers, func(p EntryPeer) bool { return p.EgressID == request.PeerID })
	ri := slices.IndexFunc(entry.Desired.Entry.Peers, func(p glivela.RoutePeer) bool { return p.EgressID == request.PeerID })
	if pi < 0 || ri < 0 {
		return publicPeerProof{}, refused
	}
	peer, route := entry.Desired.EntryNetwork.Peers[pi], entry.Desired.Entry.Peers[ri]
	if route.Transport.Protocol != "ss2022" || route.Transport.PublicAddress == "" {
		return publicPeerProof{}, refused
	}
	now := time.Now().UTC()
	for _, target := range s.nodes {
		if target.ID != request.PeerID {
			continue
		}
		if target.Desired.Landing == nil || !s.availableRuntime(target, now) || target.Receipt.ManagementIdentity == nil ||
			*target.Receipt.ManagementIdentity != peer.Identity || peer.Identity.Address != target.Desired.Landing.Address {
			return publicPeerProof{}, refused
		}
		if route.Transport.ClientListenerID != "" {
			if _, ok := s.boundClientListener(entry, target, route); !ok {
				return publicPeerProof{}, refused
			}
			return publicPeerProof{entry.ID, target.ID, entry.Desired.Revision, entry.Desired.ConfigSHA256, peer.Identity, target.Desired.Revision, target.Desired.ConfigSHA256, now}, nil
		}
		if !reflect.DeepEqual(route.Transport, target.Desired.Landing.Transport) || route.Port != target.Desired.Landing.Transport.ListenerPort() {
			return publicPeerProof{}, refused
		}
		authorized, found := target.RouteEntries[entry.ID]
		source := entry.Desired.EntryNetwork.Source
		if !found || authorized.CertificateID != cert || authorized.Address != source.Address || !slices.ContainsFunc(target.Desired.Landing.Sources, func(p landing.Source) bool {
			return p.Address == source.Address && p.TCPOnly && glivela.PublicTransportIPv4(p.PublicAddress)
		}) {
			return publicPeerProof{}, refused
		}
		return publicPeerProof{entry.ID, target.ID, entry.Desired.Revision, entry.Desired.ConfigSHA256, peer.Identity, target.Desired.Revision, target.Desired.ConfigSHA256, now}, nil
	}
	return publicPeerProof{}, refused
}

func (c *Client) VerifyPublicPeer(ctx context.Context, desired Desired, peer EntryPeer) landing.LinkResult {
	result := landing.LinkResult{State: "unknown", Reason: "peer_identity_unavailable", StartedAt: time.Now().UTC()}
	ctx, cancel := context.WithTimeout(ctx, landing.CheckTimeout)
	defer cancel()
	if desired.Entry == nil || desired.EntryNetwork == nil {
		result.CheckedAt = time.Now().UTC()
		return result
	}
	id, err := entryPlanIdentity(*desired.Entry)
	if err != nil {
		result.CheckedAt = time.Now().UTC()
		return result
	}
	var proof publicPeerProof
	err = c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).LandingAcceptance, landingAcceptanceRequest{SnapshotID: id, Revision: desired.Revision, ConfigSHA256: desired.ConfigSHA256, PeerID: peer.EgressID}, &proof, 4096, 4096)
	now := time.Now().UTC()
	if err == nil && ctx.Err() == nil && proof.EntryID == id && proof.LandingID == peer.EgressID && proof.Revision == desired.Revision && proof.ConfigSHA256 == desired.ConfigSHA256 &&
		proof.Identity == peer.Identity && proof.LandingRevision > 0 && glivela.ValidIdentity(proof.LandingConfigSHA256) && !proof.CheckedAt.Before(result.StartedAt.Add(-5*time.Second)) && !proof.CheckedAt.After(now.Add(5*time.Second)) {
		result.State, result.Reason = "authenticated", "management_identity_verified"
	}
	result.CheckedAt = now
	return result
}

func (d *NativeEntryDriver) SetPublicPeerVerifier(verify PublicPeerVerifier) {
	d.monitors.verifyPublicPeer = verify
}
func (d *EntryDriver) SetPublicPeerVerifier(verify PublicPeerVerifier) {
	d.monitors.verifyPublicPeer = verify
}
