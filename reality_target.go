package glivela

import (
	"net"
	"net/netip"
)

// ManagedLocalTLSTarget is the fixed TLS origin published on loopback by
// Vastora's managed gateway. It is not a general private-target allowance.
const ManagedLocalTLSTarget = "127.0.0.1:24483"

// ValidRealityTargetPin checks the durable hostname/port and reviewed address.
// The only non-public destination is the managed same-host TLS origin.
func ValidRealityTargetPin(target, pin string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || !validRealityTarget(target) {
		return false
	}
	if net.JoinHostPort(pin, port) == ManagedLocalTLSTarget {
		return net.ParseIP(host) == nil && validServerName(host)
	}
	ip, err := netip.ParseAddr(pin)
	return port == "443" && err == nil && ip.String() == pin && CompositePublicIP(ip)
}
