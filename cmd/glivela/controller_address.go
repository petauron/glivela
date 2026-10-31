package main

import (
	"errors"
	"net"
	"net/netip"
)

// A bridge container is assigned its private address at creation. Bind its
// single concrete address, not every interface; the installer separately binds
// the published host port to the approved private host address. Explicit private
// addresses remain exact. Ambiguous or missing interfaces fail closed.
func privateControllerAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.New("invalid private controller address")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", errors.New("controller address must be an IP literal")
	}
	if !ip.IsUnspecified() {
		return address, nil
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", errors.New("private controller interface unavailable")
	}
	var selected netip.Addr
	for _, candidate := range addresses {
		prefix, err := netip.ParsePrefix(candidate.String())
		if err != nil {
			continue
		}
		local := prefix.Addr().Unmap()
		if local.Is4() != ip.Is4() || !local.IsPrivate() || local.IsLoopback() || local.IsLinkLocalUnicast() {
			continue
		}
		if selected.IsValid() && selected != local {
			return "", errors.New("multiple private controller addresses; configure one explicitly")
		}
		selected = local
	}
	if !selected.IsValid() {
		return "", errors.New("no private controller address available")
	}
	return net.JoinHostPort(selected.String(), port), nil
}
