package glivela

import (
	"errors"
	"net/netip"
	"slices"
)

// PublicSSHPolicy decodes the retired optional SSH policy in immutable historical
// artifacts and exact firewall cleanup only. New desired builders remove it;
// there is no management API or maintenance command that enables this policy.
type PublicSSHPolicy struct {
	HostPublicAddresses []string `json:"hostPublicAddresses"`
	AddressesComplete   bool     `json:"addressesComplete"`
}

func (p *PublicSSHPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if !p.AddressesComplete || len(p.HostPublicAddresses) == 0 || len(p.HostPublicAddresses) > 128 {
		return errors.New("glivela: public SSH requires a complete host public-address inventory")
	}
	seen := map[string]bool{}
	for _, value := range p.HostPublicAddresses {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.String() != value || !CompositePublicIP(ip) || seen[value] {
			return errors.New("glivela: invalid host public management address")
		}
		seen[value] = true
	}
	return nil
}

func (p *PublicSSHPolicy) Clone() *PublicSSHPolicy {
	if p == nil {
		return nil
	}
	return &PublicSSHPolicy{HostPublicAddresses: slices.Clone(p.HostPublicAddresses), AddressesComplete: p.AddressesComplete}
}

// RequireHost catches omissions of already-known public literals. Hostnames
// and private NAT interfaces do not prove a complete external mapping.
func (p *PublicSSHPolicy) RequireHost(value string) error {
	if p == nil {
		return nil
	}
	ip, err := netip.ParseAddr(value)
	if err == nil && CompositePublicIP(ip) && !slices.Contains(p.HostPublicAddresses, value) {
		return errors.New("glivela: known public host address missing from SSH protection")
	}
	return nil
}
