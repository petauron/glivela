package control

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/petauron/glivela/landing"

	"github.com/petauron/glivela"
)

// NativeEntryDriver uses the same installed native worker contract as a
// landing. Only its Glivela-owned configuration and firewall role differ.
// No Docker socket, image runtime, or host operation from desired messages.
type NativeEntryDriver struct {
	SystemdDriver
	Directory  string
	monitors   entryMonitors
	readiness  entryReadiness
	executable nativeExecutableVerification
}

// Only the expensive executable digest is reused. Service, process identity,
// configuration, resources and firewall checks keep their existing cadence.
// This is process-local evidence, never persisted as an installation receipt.
type nativeExecutableVerification struct {
	mu                     sync.Mutex
	info                   os.FileInfo
	checkedAt              time.Time
	binary, digest, config string
	revision               uint64
	process                nativeEntryProcess
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
	for _, link := range desired.Entry.ClientLinks {
		if err := verifyPrivateClientInterface(link.SourceInterface, link.Source); err != nil {
			return err
		}
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

func (d *NativeEntryDriver) verifyStartupIdentity(ctx context.Context, desired Desired) error {
	if err := d.plan(desired); err != nil {
		return err
	}
	if desired.EntryNetwork.Source == nil {
		return nil
	}
	checker := landing.NewLinkChecker()
	defer checker.Close()
	return verifyStartupSelfIdentity(ctx, *desired.EntryNetwork.Source, checker)
}

func verifyStartupSelfIdentity(ctx context.Context, expected landing.PeerIdentity, checker *landing.LinkChecker) error {
	identity, err := checker.SelfIdentity(ctx, expected.Address)
	if err != nil || identity != expected {
		return errors.New("control: startup entry identity unavailable or changed")
	}
	return nil
}

func (d *NativeEntryDriver) policy(desired Desired) (landing.EntryFirewall, error) {
	policy := landing.EntryFirewall{PublicSSH: desired.Entry.PublicSSH.Clone(), UID: d.WorkerUID, Revision: desired.Revision}
	for _, link := range desired.Entry.ClientLinks {
		if err := verifyPrivateClientInterface(link.SourceInterface, link.Source); err != nil {
			return landing.EntryFirewall{}, err
		}
		policy.PrivateClients = append(policy.PrivateClients, link)
	}
	for _, endpoint := range desired.Entry.RealityEndpoints {
		if endpoint.Target == glivela.ManagedLocalTLSTarget {
			policy.LocalTLSOrigin = true
		}
	}
	for _, peer := range desired.EntryNetwork.Peers {
		for _, route := range desired.Entry.Peers {
			if route.PeerKey() == peer.PeerKey() {
				dial := route.DialTransport()
				address := dial.Endpoint(route.Address)
				if !slices.Contains(policy.Peers, address) {
					policy.Peers = append(policy.Peers, address)
				}
				if dial.Port != 0 {
					if policy.PeerPorts == nil {
						policy.PeerPorts = map[string]int{}
					}
					if old := policy.PeerPorts[address]; old == 0 {
						policy.PeerPorts[address] = dial.Port
					} else if old != dial.Port {
						if policy.ExtraPeerPorts == nil {
							policy.ExtraPeerPorts = map[string][]int{}
						}
						if !slices.Contains(policy.ExtraPeerPorts[address], dial.Port) {
							policy.ExtraPeerPorts[address] = append(policy.ExtraPeerPorts[address], dial.Port)
						}
					}
				}
			}
		}
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
		transport := glivela.PrivateTransport{}
		for _, route := range desired.Entry.Peers {
			if route.PeerKey() == peer.PeerKey() {
				transport = route.DialTransport()
			}
		}
		gate, err := landing.NewHostGate(peer.Identity, d.WorkerGID, desired.Revision, transport)
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

// verifiedProcess starts a single observation. Its caller must re-read the
// generation after the guarded work; this snapshot never survives that call.
func (d *NativeEntryDriver) verifiedProcess(ctx context.Context, desired Desired) (nativeEntryProcess, error) {
	if err := d.plan(desired); err != nil {
		return nativeEntryProcess{}, err
	}
	if err := d.verifyLoadedService(ctx); err != nil {
		return nativeEntryProcess{}, err
	}
	process, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil || !process.Active || process.PID <= 0 || process.ControlPID != 0 {
		return nativeEntryProcess{}, errors.New("control: native entry process not ready")
	}
	if err := verifyNativeEntryProcess(d.SystemdDriver, process, desired); err != nil {
		return nativeEntryProcess{}, err
	}
	return process, nil
}

var errNativeEntryChanged = errors.New("control: native entry changed during observation")

func (d *NativeEntryDriver) verifySameProcess(ctx context.Context, before nativeEntryProcess) error {
	after, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil {
		return err
	}
	if before != after {
		return errNativeEntryChanged
	}
	return nil
}

func (d *NativeEntryDriver) readyProcess(ctx context.Context, desired Desired) error {
	before, err := d.verifiedProcess(ctx, desired)
	if err != nil {
		return err
	}
	return d.verifySameProcess(ctx, before)
}

func (d *NativeEntryDriver) Activate(ctx context.Context, desired Desired, previous *Desired) (result error) {
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
	d.readiness.reset()
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
	defer func() {
		if result != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			result = errors.Join(result, d.Stop(cleanup, desired))
		}
	}()
	return d.warmup(ctx, desired)
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
	_, err := d.healthyProcess(ctx, desired)
	return err
}

func (d *NativeEntryDriver) healthyProcess(ctx context.Context, desired Desired) (nativeEntryProcess, error) {
	before, err := d.verifiedProcess(ctx, desired)
	if err != nil {
		return nativeEntryProcess{}, err
	}
	if err := verifyEntryConfigFile(filepath.Join(d.Directory, "config.json"), desired.Config); err != nil {
		return nativeEntryProcess{}, err
	}
	policy, err := d.policy(desired)
	if err != nil {
		return nativeEntryProcess{}, err
	}
	if err := policy.Verify(ctx); err != nil {
		return nativeEntryProcess{}, err
	}
	if err := d.monitors.verify(desired); err != nil {
		return nativeEntryProcess{}, err
	}
	if err := d.warmupFromProcess(ctx, desired, before); err != nil {
		return nativeEntryProcess{}, err
	}
	return before, nil
}

// observe verifies health and accounting together, with fresh generation reads
// bracketing both health acceptance and the subsequent counter query.
func (d *NativeEntryDriver) observe(ctx context.Context, desired Desired) (bool, *EntryTraffic) {
	before, err := d.healthyProcess(ctx, desired)
	if err != nil {
		return false, nil
	}
	traffic, err := d.trafficFromProcess(ctx, desired, before)
	if errors.Is(err, errNativeEntryChanged) {
		return false, nil
	}
	if err != nil {
		return true, nil
	}
	// Accounting failure does not authorize restarting a healthy worker. Missing
	// counters stay missing; the next observation performs all checks anew.
	return true, traffic
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

func (d *NativeEntryDriver) warmup(ctx context.Context, desired Desired) error {
	before, err := d.verifiedProcess(ctx, desired)
	if err != nil {
		return err
	}
	return d.warmupFromProcess(ctx, desired, before)
}

func (d *NativeEntryDriver) warmupFromProcess(ctx context.Context, desired Desired, before nativeEntryProcess) error {
	return d.readiness.check(ctx, func() (string, error) {
		p, err := inspectNativeEntry(ctx, d.SystemdDriver)
		if err != nil || !p.Active || p != before {
			return "", errors.New("control: entry process unavailable")
		}
		return strconv.Itoa(p.PID) + ":" + p.Invocation + ":" + p.StartedAt + ":" + desired.ConfigSHA256 + ":" + strconv.FormatUint(desired.Revision, 10), nil
	}, func(ctx context.Context) error {
		gates, err := d.gates(desired)
		if err != nil {
			return err
		}
		id, err := entryPlanIdentity(*desired.Entry)
		if err != nil {
			return err
		}
		plan, err := nativeWarmupPlan(desired)
		if err != nil {
			return err
		}
		probe := func(ctx context.Context) error {
			if err := probeEntryReadiness(ctx, d.Binary, d.BinarySHA256, plan, true); err != nil {
				return err
			}
			ready := func(check context.Context, want Desired) error {
				if err := d.readyProcess(check, want); err != nil {
					return err
				}
				return d.verifySameProcess(check, before)
			}
			return d.monitors.start(ctx, desired, gates, id, ready, nil, func(ctx context.Context, p RouteProbe) (RouteProbeResult, error) {
				return ProbeWithCore(ctx, p, d.Binary, d.BinarySHA256)
			})
		}
		if _, err := os.Lstat(filepath.Join(d.Directory, "transport-prepared.json")); errors.Is(err, os.ErrNotExist) {
			return probe(ctx)
		} else if err != nil {
			return err
		}
		runtime := NativeRuntime{Directory: d.Directory, Driver: d}
		saved, _, err := runtime.transportPreparation()
		if err != nil {
			return err
		}
		fence, err := d.transportFence(saved.Desired)
		if err != nil {
			return err
		}
		if saved.Acknowledged && fence.VerifyAbsent(ctx) == nil {
			return probe(ctx)
		}
		return fence.WithLocalProbe(ctx, probe)
	})
}

// readyProcess verifies the owned worker's exact listener before and after this
// probe. Published addresses may lack NAT reflection or host-port hairpinning;
// warm that same worker locally, then verify public ingress from an external
// client. This never changes the advertised configuration or trusts a fallback.
func nativeWarmupPlan(desired Desired) (glivela.XrayPlan, error) {
	if desired.Entry == nil {
		return glivela.XrayPlan{}, errors.New("control: native warmup requires entry plan")
	}
	plan := *desired.Entry
	plan.RealityEndpoints = slices.Clone(plan.RealityEndpoints)
	for i := range plan.RealityEndpoints {
		endpoint := &plan.RealityEndpoints[i]
		address, err := netip.ParseAddr(endpoint.ListenAddress)
		if err != nil || endpoint.ListenPort < 1 || endpoint.ListenPort > 65535 {
			return glivela.XrayPlan{}, errors.New("control: native warmup listener invalid")
		}
		if address.IsUnspecified() {
			if address.Is4() {
				address = netip.MustParseAddr("127.0.0.1")
			} else {
				address = netip.IPv6Loopback()
			}
		}
		endpoint.AdvertiseHost, endpoint.AdvertisePort = address.String(), endpoint.ListenPort
	}
	return plan, nil
}
