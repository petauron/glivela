package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

type landingAcceptanceRequest struct {
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

func handleLandingAcceptance(repository Repository, w http.ResponseWriter, r *http.Request) {
	store, ok := repository.(*Store)
	if !ok {
		http.Error(w, "unavailable", http.StatusNotFound)
		return
	}
	var request landingAcceptanceRequest
	if decode(http.MaxBytesReader(w, r.Body, 4096), &request) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	status, err := store.ownLandingAcceptance(CertificateID(r.TLS.PeerCertificates[0]), request)
	if err != nil {
		http.Error(w, "acceptance refused", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (c *Client) verifyLandingAcceptance(ctx context.Context, snapshot string, revision uint64, digest string) error {
	endpoint, err := url.Parse(c.endpoint)
	if err != nil {
		return err
	}
	endpoint.Path = "/v1/landing-acceptance"
	raw, err := json.Marshal(landingAcceptanceRequest{snapshot, revision, digest})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("control: landing acceptance unavailable")
	}
	defer response.Body.Close()
	var status RouteAcceptance
	if response.StatusCode != http.StatusOK || decode(io.LimitReader(response.Body, 4097), &status) != nil || !status.RuntimeReady || !status.RoutesPassed || status.Reason != "verified" {
		return errors.New("control: complete fresh landing route acceptance required")
	}
	return nil
}
