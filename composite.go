package meridian

import (
	"errors"
	"net/netip"
)

// Composite routes keep one client credential and one quota membership. The
// private transport family is independent of each exit's final public family.
func ValidateCompositePeers(grant RouteGrant, ipv6, ipv4 RoutePeer) error {
	if grant.Validate() != nil || grant.IPv4EgressID == "" || ipv6.EgressID != grant.EgressID || ipv4.EgressID != grant.IPv4EgressID {
		return errors.New("glivela: composite exit authority does not match the route")
	}
	return ValidateCompositeExitPair(ipv6, ipv4)
}

func ValidateCompositeExitPair(ipv6, ipv4 RoutePeer) error {
	if ipv6.Validate() != nil || ipv4.Validate() != nil || ipv6.EgressID == ipv4.EgressID || ipv6.Address == ipv4.Address ||
		ipv6.ExitFamily != EgressIPv6Only || ipv4.ExitFamily != EgressIPv4Only || !ipv6.Ready || !ipv4.Ready {
		return errors.New("glivela: composite exits must be independently authorized, ready, and strictly IPv6/IPv4")
	}
	return nil
}

// Explicit networks keep the safety boundary independent of geoip asset updates.
var compositeBlockedCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/3", "4000::/2", "8000::/1", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
}

var compositeBlockedPorts = []int{22, 23, 135, 139, 445, 1080, 1433, 1521, 2053, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 6443, 8006, 9000, 9090, 9100, 10000}

// CompositePublicIP validates reported public exit addresses before publication.
func CompositePublicIP(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.Is4In6() || address.Zone() != "" {
		return false
	}
	for _, value := range compositeBlockedCIDRs {
		if netip.MustParsePrefix(value).Contains(address) {
			return false
		}
	}
	return true
}
