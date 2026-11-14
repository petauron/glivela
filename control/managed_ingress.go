package control

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// ManagedIngressResource is the public portion of a generic DNS resource.
// Provisioning passes it through the authenticated management API. Glivela
// never receives the provider's DNS key or the host manager's admin session.
// Extra provider metadata is intentionally not part of this portable contract.
type ManagedIngressResource struct {
	ID               string `json:"id"`
	Hostname         string `json:"hostname"`
	Address          string `json:"address"`
	SecondaryAddress string `json:"secondaryAddress,omitempty"`
	Type             string `json:"type"`
	Revision         int64  `json:"revision"`
	AppliedRevision  int64  `json:"appliedRevision"`
	Status           string `json:"status"`
}

func (s *Store) managedIngressHost(ctx context.Context, input AdvertiseHostChange) (string, error) {
	invalid := errors.New("control: managed ingress requires a ready DNS-only resource for the existing public entry address")
	var resource ManagedIngressResource
	if input.Action != "apply" || len(input.Resource) > 4096 || json.Unmarshal(input.Resource, &resource) != nil || !glivela.ValidIdentifier(resource.ID) || resource.Status != "ready" || resource.Revision < 1 || resource.AppliedRevision != resource.Revision || resource.Hostname == "" || net.ParseIP(resource.Hostname) != nil || strings.ContainsAny(resource.Hostname, "/:@ \t\r\n") || input.Host != "" && input.Host != resource.Hostname {
		return "", invalid
	}
	address, err := netip.ParseAddr(resource.Address)
	if err != nil || !landing.PublicIP(address) || resource.Type != "A" && resource.Type != "AAAA" || (resource.Type == "A") != address.Is4() {
		return "", invalid
	}
	allowed := map[netip.Addr]bool{address.Unmap(): true}
	if resource.SecondaryAddress != "" {
		secondary, err := netip.ParseAddr(resource.SecondaryAddress)
		if err != nil || !landing.PublicIP(secondary) || secondary.Is4() == address.Is4() || secondary.String() != resource.SecondaryAddress {
			return "", invalid
		}
		allowed[secondary.Unmap()] = true
	}
	var previous string
	s.mu.Lock()
	if s.business != nil && !s.business.faulted {
		for _, endpoint := range s.business.material.Endpoints {
			if endpoint.Reality.EntryID == input.EntryID && !endpoint.Retired && endpoint.VLESSEnabled && (endpoint.DesiredRevision == input.ExpectedRevision || input.ExpectedRevision < math.MaxUint64 && endpoint.DesiredRevision == input.ExpectedRevision+1 && endpoint.Reality.AdvertiseHost == resource.Hostname) {
				if slices.Contains(endpoint.Reality.ServerNames, resource.Hostname) {
					s.mu.Unlock()
					return "", errors.New("control: ingress domain must remain separate from the current SNI")
				}
				previous = endpoint.Reality.AdvertiseHost
				break
			}
		}
	}
	s.mu.Unlock()
	if previous == "" {
		return "", invalid
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Match both the retained entry and the proposed name to the same address.
	// This is a bounded provisioning check, not a runtime probe or auto-withdrawal.
	for _, host := range []string{previous, resource.Hostname} {
		ips, err := net.DefaultResolver.LookupNetIP(check, "ip", host)
		if err != nil || len(ips) == 0 {
			return "", invalid
		}
		seen := map[netip.Addr]bool{}
		for _, ip := range ips {
			if !allowed[ip.Unmap()] {
				return "", invalid
			}
			seen[ip.Unmap()] = true
		}
		if len(seen) != len(allowed) {
			return "", invalid
		}
	}
	return resource.Hostname, nil
}
