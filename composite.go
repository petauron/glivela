package meridian

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// Composite routes keep one client credential and one quota membership. The
// private transport family is independent of each exit's final public family.
const CompositeMinimumXrayVersion = "26.10.10"
const CompositeRuntimeCapability = "GlivelaTargetSelectionRevision: 1"
const CompositeDNSAddress = "127.0.0.1:10086"

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

type DNSStatus string

const (
	DNSSuccess  DNSStatus = "success"
	DNSNoData   DNSStatus = "nodata"
	DNSNotFound DNSStatus = "nxdomain"
	DNSFailure  DNSStatus = "failure"
	DNSTimeout  DNSStatus = "timeout"
)

type FamilyAnswer struct {
	Status    DNSStatus
	Addresses []netip.Addr
}

type DestinationSelection struct {
	Family    EgressPolicy
	Reason    string
	Addresses []netip.Addr
}

// SelectCompositeDestination consumes host-supplied DNS evidence. It performs
// no I/O and never turns lookup failure or blocked answers into IPv4 fallback.
func SelectCompositeDestination(target string, port int, aaaa, a FamilyAnswer) (DestinationSelection, error) {
	if !CompositePortAllowed(port) {
		return DestinationSelection{}, errors.New("glivela: target port is blocked")
	}
	if literal, err := netip.ParseAddr(target); err == nil {
		literal = literal.Unmap()
		if !CompositePublicIP(literal) {
			return DestinationSelection{}, errors.New("glivela: literal target is blocked")
		}
		family := EgressIPv6Only
		if literal.Is4() {
			family = EgressIPv4Only
		}
		return DestinationSelection{Family: family, Reason: "literal", Addresses: []netip.Addr{literal}}, nil
	}
	if !CompositeHostnameAllowed(target) {
		return DestinationSelection{}, errors.New("glivela: a trustworthy destination is required")
	}
	if aaaa.Status == DNSSuccess {
		addresses, err := validateFamilyAnswer(aaaa.Addresses, false)
		if err != nil {
			return DestinationSelection{}, err
		}
		return DestinationSelection{Family: EgressIPv6Only, Reason: "public_aaaa", Addresses: addresses}, nil
	}
	if aaaa.Status != DNSNoData || len(aaaa.Addresses) != 0 {
		return DestinationSelection{}, errors.New("glivela: AAAA lookup failed; IPv4 selection is prohibited")
	}
	if a.Status != DNSSuccess {
		return DestinationSelection{}, errors.New("glivela: no usable public destination")
	}
	addresses, err := validateFamilyAnswer(a.Addresses, true)
	if err != nil {
		return DestinationSelection{}, err
	}
	return DestinationSelection{Family: EgressIPv4Only, Reason: "aaaa_nodata_public_a", Addresses: addresses}, nil
}

func validateFamilyAnswer(input []netip.Addr, ipv4 bool) ([]netip.Addr, error) {
	if len(input) == 0 || len(input) > 256 {
		return nil, errors.New("glivela: empty or oversized DNS answer")
	}
	addresses := slices.Clone(input)
	for _, address := range addresses {
		if address.Is4() != ipv4 || address.Is4In6() || !CompositePublicIP(address) {
			return nil, errors.New("glivela: DNS destination is blocked or has the wrong family")
		}
	}
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addresses), nil
}

// The exact same lists generate the runtime script and protect host DNS
// answers. Do not use geoip assets whose content can change independently.
var compositeBlockedCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/3", "4000::/2", "8000::/1", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
}

var compositeBlockedPorts = []int{22, 23, 135, 139, 445, 1080, 1433, 1521, 2053, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 6443, 8006, 9000, 9090, 9100, 10000}

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

func CompositePortAllowed(port int) bool {
	return validPort(port) && !slices.Contains(compositeBlockedPorts, port)
}

// Only genuine hostnames may enter the business resolver. IP literals must use
// SelectCompositeDestination directly, never an upstream DNS query.
func CompositeHostnameAllowed(value string) bool {
	_, err := netip.ParseAddr(value)
	if err == nil || !validServerName(value) || !strings.Contains(value, ".") {
		return false
	}
	name := strings.ToLower(value)
	for _, suffix := range []string{"lan", "localdomain", "example", "invalid", "localhost", "test", "local", "home.arpa", "internal"} {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return false
		}
	}
	return true
}
