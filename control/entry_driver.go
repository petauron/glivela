package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/petauron/glivela/landing"
)

// EntryDriver applies configuration to one already-owned Docker entry. It is
// not an adopter, container creator, image updater or remote command API. Use
// it only behind NativeRuntime's durable intent/backup/recovery transaction.
// Node bootstrap may select this driver only with its explicit local ownership
// record. A name, remote desired plan or matching legacy label cannot adopt it.
type EntryDriver struct {
	Container            EntryContainer
	Directory            string // private node journal; never mounted into the worker
	binary, binarySHA256 string
	docker               func(context.Context, ...string) ([]byte, error)
	process              func(EntryContainer, entryContainerState, Desired) error
	links                func() *landing.LinkChecker
	monitors             entryMonitors
}

func ResolveEntryDriver(container EntryContainer, directory, distribution string) (*EntryDriver, error) {
	d := &EntryDriver{Container: container, Directory: directory}
	if d.Binding() == "" {
		return nil, errors.New("control: invalid local entry installation")
	}
	if err := d.checkDirectories(); err != nil {
		return nil, err
	}
	core, err := (SystemdDriver{Distribution: distribution}).resolveDistribution(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	d.binary, d.binarySHA256 = core.Binary, core.BinarySHA256
	return d, nil
}

func (d *EntryDriver) Binding() string {
	if d == nil || d.Container.validate() != nil || !filepath.IsAbs(d.Directory) || filepath.Clean(d.Directory) != d.Directory || entryPathsOverlap(d.Directory, d.Container.ConfigurationDirectory) {
		return ""
	}
	// Stable installation identity deliberately excludes the versioned image
	// and container IDs. Replacing those later still requires an owned,
	// separately journaled resource transition, not a new application identity.
	raw, _ := json.Marshal(struct {
		App, Journal, Configuration, Network, NetworkName, Bridge, NetworkAddress string
		Aliases                                                                   []string
		UID, GID                                                                  uint32
	}{d.Container.ApplicationID, d.Directory, d.Container.ConfigurationDirectory, d.Container.NetworkID, d.Container.NetworkName, d.Container.Bridge, d.Container.NetworkAddress, d.Container.Aliases, d.Container.UID, d.Container.GID})
	h := sha256.Sum256(raw)
	return "glivela-entry-runtime-v1:" + hex.EncodeToString(h[:])
}

func (d *EntryDriver) plan(desired Desired) error {
	if d.Binding() == "" || desired.Entry == nil || desired.Landing != nil || desired.Validate() != nil {
		return errors.New("control: exact owned entry role required")
	}
	id, err := entryPlanIdentity(*desired.Entry)
	if err != nil || id != d.Container.ApplicationID {
		return errors.New("control: entry application identity differs")
	}
	return nil
}

func (d *EntryDriver) command(ctx context.Context, args ...string) ([]byte, error) {
	if d.docker != nil {
		return d.docker(ctx, args...)
	}
	return runEntryDocker(ctx, args...)
}

func (d *EntryDriver) inspect(ctx context.Context, desired Desired) (entryContainerState, error) {
	var state entryContainerState
	if err := d.plan(desired); err != nil {
		return state, err
	}
	raw, err := d.command(ctx, "container", "inspect", "--format", entryInspectTemplate, d.Container.ContainerID)
	if err != nil {
		return state, err
	}
	state, err = decodeEntryContainer(raw)
	if err != nil {
		return state, err
	}
	if err = d.Container.verifyState(desired, state); err != nil {
		return state, err
	}
	if d.Container.GID == 0 {
		raw, err = d.command(ctx, "network", "inspect", "--format", entryBridgeTemplate, d.Container.NetworkID)
		if err != nil {
			return state, err
		}
		if err = d.Container.verifyBridgeState(raw); err != nil {
			return state, err
		}
	}
	return state, nil
}

func (d *EntryDriver) Validate(ctx context.Context, desired Desired, config string) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	if err := d.checkDirectories(); err != nil {
		return err
	}
	if config != filepath.Join(d.Directory, "candidate.json") && config != filepath.Join(d.Directory, "config.json") {
		return errors.New("control: unowned entry candidate path")
	}
	if err := verifyEntryConfigFile(config, desired.Config); err != nil {
		return err
	}
	// Reject an unjournaled working configuration BEFORE NativeRuntime saves
	// mutation intent. Otherwise its first-install failure recovery could stop
	// a service whose configuration was never accepted for handover.
	if err := d.checkKnownWorkerConfig(desired); err != nil {
		return err
	}
	if err := validateXrayFile(ctx, d.binary, d.binarySHA256, config); err != nil {
		return err
	}
	_, err := d.inspect(ctx, desired)
	return err // Candidate syntax and local ownership precede any mutation.
}

func (d *EntryDriver) gates(desired Desired) ([]*landing.TrafficGate, error) {
	if err := d.plan(desired); err != nil {
		return nil, err
	}
	gates := make([]*landing.TrafficGate, 0, len(desired.EntryNetwork.Peers))
	for _, peer := range desired.EntryNetwork.Peers {
		var gate *landing.TrafficGate
		var err error
		if d.Container.GID != 0 {
			gate, err = landing.NewHostGate(peer.Identity, d.Container.GID, desired.Revision)
		} else {
			gate, err = landing.NewBridgeGate(peer.Identity, d.Container.Bridge, desired.Revision)
		}
		if err != nil {
			return nil, err
		}
		gates = append(gates, gate)
	}
	return gates, nil
}

func (d *EntryDriver) stopOwned(ctx context.Context, desired Desired) error {
	state, err := d.inspect(ctx, desired)
	if err != nil {
		return err
	}
	var stopErr error
	if state.State.Running || state.State.Restarting || state.State.Pid != 0 {
		_, stopErr = d.command(ctx, "container", "stop", "--time", "3", d.Container.ContainerID)
	}
	state, err = d.inspect(ctx, desired)
	if err != nil || state.State.Running || state.State.Restarting || state.State.Pid != 0 || state.State.Status != "exited" && state.State.Status != "created" {
		return errors.Join(stopErr, err, errors.New("control: owned entry stop was not confirmed"))
	}
	return nil // A lost stop response is harmless only after actual read-back.
}

func (d *EntryDriver) Activate(ctx context.Context, desired Desired, previous *Desired) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	if previous != nil {
		if err := d.plan(*previous); err != nil {
			return err
		}
	}
	if err := d.checkDirectories(); err != nil {
		return err
	}
	if err := verifyEntryConfigFile(filepath.Join(d.Directory, "config.json"), desired.Config); err != nil {
		return err
	}
	if err := d.checkWorkerConfig(desired, previous); err != nil {
		return err
	}
	if _, err := d.inspect(ctx, desired); err != nil {
		return err
	}
	// Resume a previously journaled unchanged core/transport only after
	// actual process checks. Probe-only changes still reapply their gates.
	resume := previous != nil && bytes.Equal(previous.Config, desired.Config) && sameEntryTransport(previous.EntryNetwork, desired.EntryNetwork) && verifyEntryConfigFile(filepath.Join(d.Container.ConfigurationDirectory, "config.json"), desired.Config) == nil && d.readyProcess(ctx, desired) == nil
	if err := d.monitors.close(ctx); err != nil {
		return err
	}
	currentGates, err := d.gates(desired)
	if err != nil {
		return err
	}
	for _, gate := range currentGates {
		if err := gate.Install(ctx); err != nil {
			return err
		}
	}
	var oldGates []*landing.TrafficGate
	if previous != nil && previous.Revision != desired.Revision {
		oldGates, err = d.gates(*previous)
		if err != nil {
			return err
		}
		for _, gate := range oldGates {
			if err := gate.Install(ctx); err != nil {
				return err
			}
		}
	}
	if !resume {
		if err := d.stopOwned(ctx, desired); err != nil {
			return err
		}
		// Never mount the private journal/recovery directory into the worker.
		if err := d.writeWorkerConfig(desired.Config); err != nil {
			return err
		}
	}
	for _, gate := range oldGates {
		if err := gate.Remove(ctx); err != nil {
			return err
		}
	}
	for _, gate := range currentGates {
		if err := gate.RemoveClosedConflicts(ctx); err != nil {
			return err
		}
	}
	if !resume {
		if _, err := d.command(ctx, "container", "start", d.Container.ContainerID); err != nil {
			return errors.New("control: owned entry start failed")
		}
	}
	ready, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if err := d.readyProcess(ready, desired); err == nil {
			break
		}
		select {
		case <-ready.Done():
			return errors.New("control: owned entry process/listeners not ready")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return d.startMonitors(desired, currentGates)
}

func (d *EntryDriver) Stop(ctx context.Context, desired Desired) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	if _, err := d.inspect(ctx, desired); err != nil {
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
	return d.stopOwned(ctx, desired)
}

func (d *EntryDriver) readyProcess(ctx context.Context, desired Desired) error {
	state, err := d.inspect(ctx, desired)
	if err != nil {
		return err
	}
	started, timeErr := time.Parse(time.RFC3339Nano, state.State.StartedAt)
	if !state.State.Running || state.State.Restarting || state.State.Paused || state.State.Dead || state.State.Pid <= 0 || state.State.Status != "running" || timeErr != nil || started.IsZero() || started.After(time.Now()) {
		return errors.New("control: owned entry process is not running")
	}
	verify := d.process
	if verify == nil {
		verify = verifyEntryProcess
	}
	if err := verify(d.Container, state, desired); err != nil {
		return err
	}
	after, err := d.inspect(ctx, desired)
	if err != nil || after.State != state.State {
		return errors.New("control: entry process changed during acceptance")
	}
	return nil
}

func (d *EntryDriver) Healthy(ctx context.Context, desired Desired) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	if err := d.checkDirectories(); err != nil {
		return err
	}
	if err := verifyEntryConfigFile(filepath.Join(d.Directory, "config.json"), desired.Config); err != nil {
		return err
	}
	if err := d.readyProcess(ctx, desired); err != nil {
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

// Close fences private routes on node-process shutdown, but does not stop the
// proxy or destroy its last configuration. Native entries need no monitors.
func (d *EntryDriver) Close(ctx context.Context) error { return d.monitors.close(ctx) }

func verifyEntryConfigFile(path string, want []byte) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxMessage {
		return errors.New("control: unsafe entry configuration")
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, want) {
		return errors.New("control: entry configuration differs")
	}
	return nil
}
