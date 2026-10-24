package control

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"time"

	"github.com/petauron/glivela/landing"
)

// NativeEntryDriver uses the same installed native worker contract as a
// landing. Only its Glivela-owned configuration and firewall role differ.
// No Docker socket, image runtime, or host operation from desired messages.
type NativeEntryDriver struct {
	SystemdDriver
	Directory string
	monitors  entryMonitors
}

func (d *NativeEntryDriver) Binding() string {
	return "native-entry:" + d.SystemdDriver.Binding() + ":" + strconv.FormatUint(uint64(d.WorkerGID), 10)
}

func (d *NativeEntryDriver) plan(desired Desired) error {
	if d.Role != "entry" || d.WorkerUID == 0 || d.WorkerGID == 0 || desired.Validate() != nil || desired.Entry == nil || desired.Landing != nil || !filepath.IsAbs(d.Directory) {
		return errors.New("control: explicit owned native entry required")
	}
	return nil
}

func (d *NativeEntryDriver) Validate(ctx context.Context, desired Desired, config string) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	if err := d.verifyLoadedService(ctx); err != nil {
		return err
	}
	if _, err := d.existingEntryDNS(); err != nil {
		return err
	}
	if err := verifyEntryRealityTargets(ctx, desired); err != nil {
		return err
	}
	return validateXrayFile(ctx, d.Binary, d.BinarySHA256, config)
}

func (d *NativeEntryDriver) policy(desired Desired) (landing.EntryFirewall, error) {
	policy := landing.EntryFirewall{UID: d.WorkerUID, Revision: desired.Revision}
	for _, peer := range desired.Entry.Peers {
		policy.Peers = append(policy.Peers, peer.Transport.Endpoint(peer.Address))
	}
	var err error
	policy.DNS, err = d.existingEntryDNS()
	return policy, err
}

func (d *NativeEntryDriver) gates(desired Desired) ([]*landing.TrafficGate, error) {
	if err := d.plan(desired); err != nil {
		return nil, err
	}
	var gates []*landing.TrafficGate
	for _, peer := range desired.EntryNetwork.Peers {
		publicAddress := ""
		for _, route := range desired.Entry.Peers {
			if route.EgressID == peer.EgressID {
				publicAddress = route.Transport.PublicAddress
			}
		}
		gate, err := landing.NewHostGate(peer.Identity, d.WorkerGID, desired.Revision, publicAddress)
		if err != nil {
			return nil, err
		}
		gates = append(gates, gate)
	}
	return gates, nil
}

func (d *NativeEntryDriver) stopOwned(ctx context.Context, desired Desired) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	return d.SystemdDriver.stopOwned(ctx)
}

func (d *NativeEntryDriver) readyProcess(ctx context.Context, desired Desired) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	if err := d.verifyLoadedService(ctx); err != nil {
		return err
	}
	before, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil || !before.Active || before.PID <= 0 || before.ControlPID != 0 {
		return errors.New("control: native entry process not ready")
	}
	if err := verifyNativeEntryProcess(d.SystemdDriver, before, desired); err != nil {
		return err
	}
	after, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil || before != after {
		return errors.New("control: native entry changed during acceptance")
	}
	return nil
}

func (d *NativeEntryDriver) Activate(ctx context.Context, desired Desired, previous *Desired) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	if previous != nil {
		if err := d.plan(*previous); err != nil {
			return err
		}
	}
	if err := verifyEntryConfigFile(filepath.Join(d.Directory, "config.json"), desired.Config); err != nil {
		return err
	}
	policy, err := d.policy(desired)
	if err != nil {
		return err
	}
	resume := previous != nil && bytes.Equal(previous.Config, desired.Config) && sameEntryTransport(previous.EntryNetwork, desired.EntryNetwork) && d.readyProcess(ctx, desired) == nil
	if !resume {
		if err := verifyEntryRealityTargets(ctx, desired); err != nil {
			return err
		}
	}
	if err := d.monitors.close(ctx); err != nil {
		return err
	}
	if !resume {
		if err := d.stopOwned(ctx, desired); err != nil {
			return err
		}
	}
	if err := policy.Install(ctx); err != nil {
		return err
	}
	gates, err := d.gates(desired)
	if err != nil {
		return err
	}
	for _, gate := range gates {
		if err := gate.Install(ctx); err != nil {
			return err
		}
	}
	if previous != nil && previous.Revision != desired.Revision {
		old, err := d.gates(*previous)
		if err != nil {
			return err
		}
		for _, gate := range old {
			if err := gate.Remove(ctx); err != nil {
				return err
			}
		}
		oldPolicy, err := d.policy(*previous)
		if err != nil {
			return err
		}
		if err := oldPolicy.Remove(ctx); err != nil {
			return err
		}
	}
	for _, gate := range gates {
		if err := gate.RemoveClosedConflicts(ctx); err != nil {
			return err
		}
	}
	if !resume {
		if err := d.service(ctx, "start"); err != nil {
			return err
		}
	}
	ready, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if d.readyProcess(ready, desired) == nil {
			break
		}
		select {
		case <-ready.Done():
			return errors.New("control: native entry listeners not ready")
		case <-ticker.C:
		}
	}
	id, err := entryPlanIdentity(*desired.Entry)
	if err != nil {
		return err
	}
	return d.monitors.start(desired, gates, id, d.readyProcess, d.stopOwned, nil, func(ctx context.Context, p RouteProbe) (RouteProbeResult, error) {
		return ProbeWithCore(ctx, p, d.Binary, d.BinarySHA256)
	})
}

func (d *NativeEntryDriver) Stop(ctx context.Context, desired Desired) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	if err := d.monitors.close(ctx); err != nil {
		return err
	}
	gates, err := d.gates(desired)
	if err != nil {
		return err
	}
	for _, gate := range gates {
		if err := gate.Install(ctx); err != nil {
			return err
		}
	}
	// Retain closed rules until an explicit owned transition or uninstall.
	return d.stopOwned(ctx, desired)
}

func (d *NativeEntryDriver) Healthy(ctx context.Context, desired Desired) error {
	if err := d.readyProcess(ctx, desired); err != nil {
		return err
	}
	if err := verifyEntryConfigFile(filepath.Join(d.Directory, "config.json"), desired.Config); err != nil {
		return err
	}
	policy, err := d.policy(desired)
	if err != nil {
		return err
	}
	if err := policy.Verify(ctx); err != nil {
		return err
	}
	gates, err := d.gates(desired)
	if err != nil {
		return err
	}
	for _, gate := range gates {
		if err := gate.Verify(ctx); err != nil {
			return err
		}
	}
	return d.monitors.verify(desired)
}

func (d *NativeEntryDriver) EntryHealth(desired Desired) *EntryHealthReport {
	return d.monitors.health(desired)
}
func (d *NativeEntryDriver) Close(ctx context.Context) error { return d.monitors.close(ctx) }

type nativeEntryProcess struct {
	PID, ControlPID       int
	Active                bool
	Invocation, StartedAt string
}
