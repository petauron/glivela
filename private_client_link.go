package glivela

import (
	"errors"
	"net/netip"
	"regexp"
)

// PrivateClientLink authorizes one provider-LAN socket, never a private subnet.
// Interface ownership is checked again on each owning native runtime.
type PrivateClientLink struct {
	Source          string `json:"source"`
	Address         string `json:"address"`
	SourceInterface string `json:"sourceInterface"`
	Interface       string `json:"interface"`
}

type PrivateClientPolicy struct {
	PrivateClientLink
	ID        string `json:"id"`
	AccountID string `json:"accountId"`
	Port      int    `json:"port"`
}

var privateInterfacePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func PrivateClientIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Is4() && ip.IsPrivate() && ip.String() == value
}

func (p PrivateClientLink) Validate() error {
	if !PrivateClientIPv4(p.Source) || !PrivateClientIPv4(p.Address) || p.Source == p.Address || !privateInterfacePattern.MatchString(p.SourceInterface) || !privateInterfacePattern.MatchString(p.Interface) || p.Interface == "lo" || p.SourceInterface == "lo" {
		return errors.New("glivela: exact private IPv4 addresses and interfaces required")
	}
	return nil
}
