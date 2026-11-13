package control

import (
	"errors"
	"net"
	"net/netip"
)

func verifyPrivateClientInterface(name, address string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagPointToPoint != 0 {
		return errors.New("control: private client interface unavailable")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, addr := range addresses {
		prefix, e := netip.ParsePrefix(addr.String())
		if e == nil && prefix.Addr().String() == address {
			return nil
		}
	}
	return errors.New("control: private client address is not assigned to its interface")
}
