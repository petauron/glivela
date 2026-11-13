package control

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

type AdvertiseHostChange struct {
	Resource         json.RawMessage `json:"resource,omitempty"`
	EntryID          string          `json:"entryId"`
	Action           string          `json:"action"`
	Host             string          `json:"host"`
	ExpectedRevision uint64          `json:"expectedRevision,string"`
}

type AdvertiseHostView struct {
	EntryID  string `json:"entryId"`
	Revision uint64 `json:"revision,string"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

// ChangeAdvertiseHost changes only subscription metadata. The public listener,
// SNI, credentials, counters and availability remain unchanged. Normal forward
// projection applies the new metadata and retains startup readiness checks.
// DNS and actual ingress must be verified by the operator before applying it.
func (s *Store) ChangeAdvertiseHost(ctx context.Context, input AdvertiseHostChange) (AdvertiseHostView, error) {
	if len(input.Resource) != 0 {
		host, err := s.managedIngressHost(ctx, input)
		if err != nil {
			return AdvertiseHostView{}, err
		}
		input.Host = host
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: subscription host change refused; refresh the endpoint")
	if err := ctx.Err(); err != nil {
		return AdvertiseHostView{}, err
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil || !glivela.ValidIdentifier(input.EntryID) {
		return AdvertiseHostView{}, invalid
	}
	material := s.business.material
	i := slices.IndexFunc(material.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == input.EntryID })
	if i < 0 || material.Endpoints[i].Retired || !material.Endpoints[i].VLESSEnabled || material.Endpoints[i].Hysteria != nil || realityChangePending(material.Endpoints[i]) {
		return AdvertiseHostView{}, invalid
	}
	view := func(e glivela.ImportEndpoint) AdvertiseHostView {
		return AdvertiseHostView{EntryID: e.Reality.EntryID, Revision: e.DesiredRevision, Host: e.Reality.AdvertiseHost, Port: e.Reality.AdvertisePort}
	}
	if input.Action == "inspect" {
		return view(material.Endpoints[i]), nil
	}
	endpoint := material.Endpoints[i]
	same := input.Host == endpoint.Reality.AdvertiseHost
	if input.Action != "apply" || input.ExpectedRevision == 0 || input.ExpectedRevision == math.MaxUint64 || input.Host != strings.TrimSpace(input.Host) || endpoint.DesiredRevision != input.ExpectedRevision && !(same && endpoint.DesiredRevision == input.ExpectedRevision+1) {
		return AdvertiseHostView{}, invalid
	}
	if ip, err := netip.ParseAddr(input.Host); err == nil && !landing.PublicIP(ip) {
		return AdvertiseHostView{}, invalid
	}
	if !same {
		endpoint.PreviousAdvertiseHost = endpoint.Reality.AdvertiseHost
		endpoint.Reality.AdvertiseHost = input.Host
		endpoint.DesiredRevision++
		endpoint.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if endpoint.Validate() != nil {
			return AdvertiseHostView{}, invalid
		}
		material.Endpoints = slices.Clone(material.Endpoints)
		material.Endpoints[i] = endpoint
	}
	nodes := s.copy()
	matched := false
	for _, node := range nodes {
		if node.ID != input.EntryID {
			continue
		}
		if node.Desired.Entry == nil || node.EntryQuota != nil || node.TransportTail != nil {
			return AdvertiseHostView{}, invalid
		}
		matched = true
	}
	if !matched {
		return AdvertiseHostView{}, invalid
	}
	projected, changed, err := projectBusinessEntries(nodes, material, time.Now())
	if err != nil {
		return AdvertiseHostView{}, err
	}
	if err := s.saveOwnedBusinessLocked(material); err != nil {
		return AdvertiseHostView{}, err
	}
	if changed {
		if err := s.commit(projected); err != nil {
			return AdvertiseHostView{}, err
		}
	}
	return view(endpoint), nil
}

// A lost projection write may replay only the exact previous-to-current host
// recorded in the authenticated business source. Everything else must match;
// the normal projection issues a forward revision and awaits real node receipts.
func authorizedAdvertiseHostProjection(node Node, current glivela.RealityEndpoint, endpoint glivela.ImportEndpoint) bool {
	if endpoint.PreviousAdvertiseHost == "" || current.AdvertiseHost != endpoint.PreviousAdvertiseHost {
		return false
	}
	expected, err := ownedRealityForNode(node, endpoint)
	current.AdvertiseHost = endpoint.Reality.AdvertiseHost
	return err == nil && reflect.DeepEqual(current, expected)
}
