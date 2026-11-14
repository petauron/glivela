package control

import (
	"context"
	"encoding/json"
	"errors"
	glivela "github.com/petauron/glivela"
	"math"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"time"
)

// PublicIngressChange is a single owned endpoint transition. DNS and website
// bindings must first be prepared by their own authenticated manager.
type PublicIngressChange struct {
	EntryID          string          `json:"entryId"`
	Action           string          `json:"action"`
	ExpectedRevision uint64          `json:"expectedRevision,string"`
	Resource         json.RawMessage `json:"resource,omitempty"`
}
type PublicIngressView struct {
	EntryID           string `json:"entryId"`
	Revision          uint64 `json:"revision,string"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	ListenAddress     string `json:"listenAddress"`
	IPv4ListenAddress string `json:"ipv4ListenAddress,omitempty"`
	RuntimeReady      bool   `json:"runtimeReady"`
}

func (s *Store) ChangePublicIngress(ctx context.Context, in PublicIngressChange) (PublicIngressView, error) {
	invalid := errors.New("control: public ingress change refused; prepare the exact owned DNS and local TLS backend first")
	var resource ManagedIngressResource
	if in.Action != "inspect" {
		host, err := s.managedIngressHost(ctx, AdvertiseHostChange{EntryID: in.EntryID, Action: "apply", ExpectedRevision: in.ExpectedRevision, Resource: in.Resource})
		if err != nil || json.Unmarshal(in.Resource, &resource) != nil || host != resource.Hostname {
			return PublicIngressView{}, invalid
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return PublicIngressView{}, ctx.Err()
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil || !glivela.ValidIdentifier(in.EntryID) {
		return PublicIngressView{}, invalid
	}
	material := s.business.material
	i := slices.IndexFunc(material.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == in.EntryID })
	if i < 0 {
		return PublicIngressView{}, invalid
	}
	endpoint := material.Endpoints[i]
	var node Node
	found := false
	for _, n := range s.nodes {
		if n.ID == in.EntryID {
			node = n
			found = true
			break
		}
	}
	primary, err := netip.ParseAddr(endpoint.Reality.ListenAddress)
	if err != nil || !found || endpoint.Retired || !endpoint.VLESSEnabled || endpoint.Hysteria != nil || realityChangePending(endpoint) || !primary.Is6() || !glivela.CompositePublicIP(primary) || node.Desired.Entry == nil || node.EntryQuota != nil || node.TransportTail != nil || node.PrivateListenerPort != 0 {
		return PublicIngressView{}, invalid
	}
	view := func(e glivela.ImportEndpoint) PublicIngressView {
		return PublicIngressView{EntryID: e.Reality.EntryID, Revision: e.DesiredRevision, Host: e.Reality.AdvertiseHost, Port: e.Reality.AdvertisePort, ListenAddress: e.Reality.ListenAddress, IPv4ListenAddress: e.Reality.IPv4ListenAddress, RuntimeReady: realityNodeReady(node, e, time.Now())}
	}
	if in.Action == "inspect" {
		return view(endpoint), nil
	}
	if (in.Action != "apply" && in.Action != "revert") || in.ExpectedRevision == 0 || in.ExpectedRevision == math.MaxUint64 || endpoint.Reality.AdvertiseHost != resource.Hostname {
		return PublicIngressView{}, invalid
	}
	// Same-host fallback is mandatory. Unauthenticated HTTPS uses the existing
	// certificate and page through this high loopback TLS target, never itself443.
	_, targetPort, targetErr := net.SplitHostPort(endpoint.Reality.Target)
	if targetErr != nil || endpoint.TargetIP != "127.0.0.1" || targetPort != "24483" {
		return PublicIngressView{}, invalid
	}
	desired := glivela.RealityPublicIngress{ListenPort: 443, AdvertisePort: 443}
	addresses := []string{resource.Address}
	if resource.SecondaryAddress != "" {
		addresses = append(addresses, resource.SecondaryAddress)
	}
	seenPrimary := false
	for _, a := range addresses {
		ip, e := netip.ParseAddr(a)
		if e != nil {
			return PublicIngressView{}, invalid
		}
		if ip == primary {
			seenPrimary = true
		} else if ip.Is4() {
			desired.IPv4ListenAddress = a
		} else {
			return PublicIngressView{}, invalid
		}
	}
	if !seenPrimary {
		return PublicIngressView{}, invalid
	}
	if in.Action == "revert" {
		if endpoint.PreviousPublicIngress == nil {
			return PublicIngressView{}, invalid
		}
		previous := *endpoint.PreviousPublicIngress
		if previous.IPv4ListenAddress != desired.IPv4ListenAddress {
			return PublicIngressView{}, invalid
		}
		desired = previous
	}
	current := glivela.RealityPublicIngress{ListenPort: endpoint.Reality.ListenPort, AdvertisePort: endpoint.Reality.AdvertisePort, IPv4ListenAddress: endpoint.Reality.IPv4ListenAddress}
	same := current == desired
	if endpoint.DesiredRevision != in.ExpectedRevision && !(same && endpoint.DesiredRevision == in.ExpectedRevision+1) {
		return PublicIngressView{}, invalid
	}
	if !same {
		if !realityNodeMatches(node, endpoint) {
			return PublicIngressView{}, invalid
		}
		endpoint.PreviousPublicIngress = &current
		endpoint.Reality.ListenPort = desired.ListenPort
		endpoint.Reality.AdvertisePort = desired.AdvertisePort
		endpoint.Reality.IPv4ListenAddress = desired.IPv4ListenAddress
		endpoint.DesiredRevision++
		endpoint.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if endpoint.Validate() != nil {
			return PublicIngressView{}, invalid
		}
		material.Endpoints = slices.Clone(material.Endpoints)
		material.Endpoints[i] = endpoint
	}
	nodes := s.copy()
	projected, changed, err := projectBusinessEntries(nodes, material, time.Now())
	if err != nil {
		return PublicIngressView{}, err
	}
	if err = s.saveOwnedBusinessLocked(material); err != nil {
		return PublicIngressView{}, err
	}
	if changed {
		if err = s.commit(projected); err != nil {
			return PublicIngressView{}, err
		}
	}
	return view(endpoint), nil
}
func authorizedPublicIngressProjection(node Node, current glivela.RealityEndpoint, e glivela.ImportEndpoint) bool {
	p := e.PreviousPublicIngress
	if p == nil || current.ListenPort != p.ListenPort || current.AdvertisePort != p.AdvertisePort || current.IPv4ListenAddress != p.IPv4ListenAddress {
		return false
	}
	expected, err := ownedRealityForNode(node, e)
	current.ListenPort = expected.ListenPort
	current.AdvertisePort = expected.AdvertisePort
	current.IPv4ListenAddress = expected.IPv4ListenAddress
	return err == nil && reflect.DeepEqual(current, expected)
}
