package control

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"net/netip"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

// EntryRebind is an explicit recovery of an unavailable entry, not a live
// listener migration. Account identities, routes and cumulative usage survive.
type EntryRebind struct {
	EntryID          string `json:"entryId"`
	ExpectedRevision uint64 `json:"expectedRevision,string"`
	PreviousAddress  string `json:"previousAddress"`
	Address          string `json:"address"`
}

func (s *Store) RebindEntry(ctx context.Context, change EntryRebind) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: entry recovery binding refused")
	if err := ctx.Err(); err != nil {
		return err
	}
	address, err := netip.ParseAddr(change.Address)
	if err != nil || address.String() != change.Address || !netip.MustParsePrefix("100.64.0.0/10").Contains(address) || change.Address == change.PreviousAddress || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return invalid
	}
	var certificate string
	var node Node
	for key, candidate := range s.nodes {
		if candidate.ID == change.EntryID {
			certificate, node = key, candidate
		}
	}
	if certificate == "" || node.Desired.Entry == nil || node.Desired.Revision != change.ExpectedRevision || change.ExpectedRevision == math.MaxUint64 || runtimeFresh(node, time.Now()) || node.TransportTail != nil || node.EntryQuota != nil || node.Desired.EntryNetwork == nil || node.Desired.EntryNetwork.Source == nil || node.Desired.EntryNetwork.Source.Address != change.Address {
		return invalid
	}
	material := s.business.material
	index := slices.IndexFunc(material.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == change.EntryID })
	if index < 0 || material.Endpoints[index].Retired || material.Endpoints[index].Reality.ListenAddress != change.PreviousAddress || material.Endpoints[index].Hysteria != nil {
		return invalid
	}
	if _, _, err := projectBusinessEntries(s.nodes, material, time.Now()); err != nil {
		return err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	material.Endpoints = slices.Clone(material.Endpoints)
	endpoint := &material.Endpoints[index]
	if endpoint.DesiredRevision == math.MaxUint64 {
		return invalid
	}
	endpoint.Reality.ListenAddress = change.Address
	endpoint.Reality.PrivateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
	endpoint.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	endpoint.DesiredRevision++
	endpoint.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := material.Validate(); err != nil {
		return invalid
	}
	nodes := s.copy()
	desired := node.Desired.clone()
	found := false
	for i := range desired.Entry.RealityEndpoints {
		if desired.Entry.RealityEndpoints[i].ID == endpoint.Reality.ID {
			projectedEndpoint, projectionErr := ownedRealityForNode(node, *endpoint)
			if projectionErr != nil {
				return invalid
			}
			desired.Entry.RealityEndpoints[i] = projectedEndpoint
			found = true
		}
	}
	if !found {
		return invalid
	}
	desired.Entry.Revision++
	node.Desired, err = newEntryDesiredVersion(*desired.Entry, *desired.EntryNetwork, desired.EntryRenderVersion)
	if err != nil {
		return err
	}
	node.Receipt = nil
	node.ReportedAt = time.Time{}
	node.EntryHealthBarrierAt = time.Time{}
	nodes[certificate] = node
	invalidateEntryChecks(nodes, node.ID)
	projected, _, err := projectBusinessEntries(nodes, material, time.Now())
	if err != nil {
		return err
	}
	if err := s.saveOwnedBusinessLocked(material); err != nil {
		return err
	}
	return s.commit(projected)
}
