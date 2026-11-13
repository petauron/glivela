package control

import (
	"context"
	"errors"
	pb "github.com/petauron/glivela/internal/controlpb"
)

type landingAcceptanceRequest struct {
	PeerID       string `json:"peerId,omitempty"`
	SnapshotID   string `json:"snapshotId"`
	Revision     uint64 `json:"revision"`
	ConfigSHA256 string `json:"configSha256"`
}

// The authenticated landing can only query its own complete route inventory.
// This grants no enrollment, configuration or route-assignment authority.
func (s *Store) ownLandingAcceptance(cert string, request landingAcceptanceRequest) (RouteAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.nodes[cert]
	if !ok || node.Desired.Landing == nil {
		return RouteAcceptance{}, errors.New("control: enrolled landing required")
	}
	return s.acceptLandingRoutesLocked(node.ID, request.SnapshotID, request.Revision, request.ConfigSHA256)
}

func (c *Client) verifyLandingAcceptance(ctx context.Context, snapshot string, revision uint64, digest string) (RouteAcceptance, error) {
	var result RouteAcceptance
	err := c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).LandingAcceptance, landingAcceptanceRequest{SnapshotID: snapshot, Revision: revision, ConfigSHA256: digest}, &result, 4096, 4096)
	if err != nil || !result.RuntimeReady || !result.RoutesPassed || (result.Reason != "verified" && result.Reason != "verified-active-entries") || (len(result.DeferredEntries) > 0) != (result.Reason == "verified-active-entries") {
		return RouteAcceptance{}, errors.New("control: complete fresh landing route acceptance required")
	}
	return result, nil
}
