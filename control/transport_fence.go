package control

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/petauron/glivela/landing"
)

func (d *NativeEntryDriver) transportFence(desired Desired) (landing.TransportFence, error) {
	f := landing.TransportFence{Binding: d.Binding()}
	if err := d.plan(desired); err != nil {
		return f, err
	}
	var config struct {
		Inbounds []struct {
			Tag, Listen, Protocol string
			Port                  int
		}
	}
	if json.Unmarshal(desired.Config, &config) != nil {
		return f, errors.New("control: invalid transport listeners")
	}
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "api" {
			continue
		}
		network := "tcp"
		if inbound.Protocol == "hysteria" {
			network = "udp"
		} else if inbound.Protocol != "vless" {
			return f, errors.New("control: unknown transport listener")
		}
		f.Listeners = append(f.Listeners, landing.TransportListener{Address: inbound.Listen, Port: inbound.Port, Network: network})
	}
	return f, nil
}
func (d *NativeEntryDriver) verifyTransportFence(ctx context.Context, desired Desired) error {
	f, err := d.transportFence(desired)
	if err != nil {
		return err
	}
	return f.Verify(ctx)
}
func (d *NativeEntryDriver) removeTransportFence(ctx context.Context, desired Desired) error {
	f, err := d.transportFence(desired)
	if err != nil {
		return err
	}
	return f.Remove(ctx)
}
