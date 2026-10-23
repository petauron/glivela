package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

type transportPreparation struct {
	Acknowledged bool          `json:"acknowledged,omitempty"`
	Binding      string        `json:"binding"`
	Desired      Desired       `json:"desired"`
	Tail         TransportTail `json:"tail"`
}

// The installed systemd generation timestamp has one-second precision. Start
// the replacement strictly after the final sample's second; never relax the
// ledger's generation-order validation to accommodate a fast restart.
func waitTransportGenerationBoundary(ctx context.Context, sampled time.Time) error {
	delay := time.Until(sampled.Truncate(time.Second).Add(time.Second))
	if delay <= 0 {
		return nil
	}
	if delay > time.Second {
		return errors.New("control: final sample is in the future")
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type transportFencer interface {
	verifyTransportFence(context.Context, Desired) error
	removeTransportFence(context.Context, Desired) error
}

func (r *NativeRuntime) verifyTransportMaintenance(ctx context.Context) error {
	if _, err := os.Lstat(filepath.Join(r.Directory, "transport-prepared.json")); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	saved, _, err := r.transportPreparation()
	if err != nil {
		return err
	}
	fencer, ok := r.Driver.(transportFencer)
	if !ok || saved.Acknowledged {
		return errors.New("control: transport maintenance cannot restart an acknowledged worker")
	}
	return fencer.verifyTransportFence(ctx, saved.Desired)
}

func (r *NativeRuntime) transportPreparation() (transportPreparation, []byte, error) {
	var saved transportPreparation
	path := filepath.Join(r.Directory, "transport-prepared.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 3*maxMessage {
		return saved, nil, errors.New("control: private transport checkpoint unavailable")
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &saved) != nil || r.Driver == nil || saved.Binding != r.Driver.Binding() || saved.Desired.Validate() != nil || saved.Tail.validate(saved.Desired) != nil {
		return saved, nil, errors.New("control: private transport checkpoint invalid")
	}
	return saved, raw, nil
}

// CompleteTransport applies only the controller's authenticated, paired
// transport revision. Keep the checkpoint through activation and reporting:
// a lost response must not cause a restart, a zero counter or implicit success.
// The caller holds the node directory lease for this entire operation.
func (r *NativeRuntime) CompleteTransport(ctx context.Context, client *Client) error {
	saved, raw, err := r.transportPreparation()
	if err != nil || client == nil {
		return errors.New("control: transport completion prerequisites unavailable")
	}
	desired, err := client.Exchange(ctx, nil)
	if err != nil {
		return err
	}
	previous := saved.Desired.clone()
	restored := previous.clone()
	restored.Entry.Revision = desired.Revision
	sameConfiguration := reflect.DeepEqual(restored.Entry, desired.Entry) && reflect.DeepEqual(restored.EntryNetwork, desired.EntryNetwork)
	if desired.Revision <= previous.Revision || !transportOnlyEntryChange(previous, desired) && !probeOnlyEntryChange(previous, desired) && !sameConfiguration {
		return errors.New("control: controller has not committed the paired transport change")
	}
	state, err := r.journal()
	if err != nil || state.Phase != "ready" || state.Retired || state.Current == nil {
		return errors.New("control: transport runtime requires recovery")
	}
	if !reflect.DeepEqual(*state.Current, desired) {
		if saved.Acknowledged {
			return errors.New("control: acknowledged transport generation changed")
		}
		now := time.Now().UTC()
		if saved.Tail.Traffic.SampledAt.After(now) || now.Sub(saved.Tail.Traffic.SampledAt) > time.Minute {
			return errors.New("control: final sample expired; transport activation aborted")
		}
		if !reflect.DeepEqual(*state.Current, previous) {
			return errors.New("control: transport runtime no longer matches preparation")
		}
		if err := waitTransportGenerationBoundary(ctx, saved.Tail.Traffic.SampledAt); err != nil {
			return err
		}
		if err := r.Apply(ctx, desired); err != nil {
			return err
		}
	}
	actual, err := r.Inspect(ctx)
	if err != nil || !actual.RuntimeReady || actual.Traffic == nil {
		return errors.New("control: applied transport not ready for accounting")
	}
	confirmed, err := client.Exchange(ctx, &actual)
	if err != nil || !reflect.DeepEqual(confirmed, desired) {
		return errors.New("control: applied transport acknowledgement not confirmed")
	}
	return r.finishTransportCheckpoint(ctx, saved, raw)
}

// CancelTransport restores only the unchanged, already-accounted preparation.
// An expired tail may cancel, never authorize a new transport revision.
func (r *NativeRuntime) CancelTransport(ctx context.Context, client *Client) error {
	saved, raw, err := r.transportPreparation()
	if err != nil || client == nil {
		return errors.New("control: cancellation checkpoint unavailable")
	}
	desired, err := client.TransportCancelIntent(ctx, saved.Tail)
	if err == nil {
		state, stateErr := r.journal()
		if stateErr != nil || state.Phase != "ready" || state.Retired || state.Current == nil || !reflect.DeepEqual(*state.Current, saved.Desired) || !reflect.DeepEqual(desired, saved.Desired) || r.verifyConfig(desired) != nil {
			return errors.New("control: cancellation runtime differs")
		}
		if err := r.verifyTransportMaintenance(ctx); err != nil {
			return err
		}
		if err := r.Driver.Validate(ctx, desired, filepath.Join(r.Directory, "config.json")); err != nil {
			return err
		}
		if err := waitTransportGenerationBoundary(ctx, saved.Tail.Traffic.SampledAt); err != nil {
			return err
		}
		if err := r.Driver.Activate(ctx, desired, &desired); err != nil {
			return err
		}
	} else if driver, ok := r.Driver.(*NativeEntryDriver); ok && !saved.Acknowledged {
		// If the final HTTP write never committed, preserve that process's
		// unacknowledged counters by restoring listeners without restarting it.
		state, stateErr := r.journal()
		if stateErr != nil || state.Phase != "ready" || state.Retired || state.Current == nil || !reflect.DeepEqual(*state.Current, saved.Desired) || r.verifyConfig(saved.Desired) != nil {
			return errors.New("control: cancellation runtime differs")
		}
		if err := driver.restorePreparedListeners(ctx, saved.Desired, saved.Tail.Traffic); err != nil {
			return err
		}
		if err := driver.Activate(ctx, saved.Desired, &saved.Desired); err != nil {
			return err
		}
	}
	// On a lost cancellation response, inspect and re-acknowledge the same
	// running generation; never restart merely because an HTTP request failed.
	actual, inspectErr := r.Inspect(ctx)
	if inspectErr != nil || !actual.RuntimeReady || actual.Traffic == nil || actual.Revision != saved.Desired.Revision || actual.ConfigSHA256 != saved.Desired.ConfigSHA256 {
		return errors.New("control: cancellation restoration not verified")
	}
	_ = client.ResumeTransportPreparation(ctx, actual)
	confirmed, err := client.Exchange(ctx, &actual)
	if err != nil || !reflect.DeepEqual(confirmed, saved.Desired) {
		return errors.New("control: cancellation accounting not acknowledged")
	}
	return r.finishTransportCheckpoint(ctx, saved, raw)
}

func (r *NativeRuntime) finishTransportCheckpoint(ctx context.Context, saved transportPreparation, raw []byte) error {
	previous := saved.Desired
	var err error
	fencer, ok := r.Driver.(transportFencer)
	if !ok {
		return errors.New("control: transport fence unavailable")
	}
	if !saved.Acknowledged {
		if err := fencer.verifyTransportFence(ctx, previous); err != nil {
			return err
		}
		saved.Acknowledged = true
		raw, err = json.Marshal(saved)
		if err != nil {
			return err
		}
		if err := replacePrivate(r.Directory, "transport-prepared.json", raw); err != nil {
			return err
		}
	}
	if err := fencer.removeTransportFence(ctx, previous); err != nil {
		return err
	}
	// Archive the exact private checkpoint, never restore its accounting.
	name := fmt.Sprintf("transport-completed-%d-%s-%d.json", saved.Desired.Revision, saved.Desired.ConfigSHA256, saved.Tail.Traffic.SampledAt.UnixNano())
	if existing, err := os.ReadFile(filepath.Join(r.Directory, name)); err == nil && !reflect.DeepEqual(existing, raw) {
		return errors.New("control: transport archive conflict")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := replacePrivate(r.Directory, name, raw); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(r.Directory, "transport-prepared.json")); err != nil {
		return err
	}
	directory, err := os.Open(r.Directory)
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	if err != nil {
		if restoreErr := replacePrivate(r.Directory, "transport-prepared.json", raw); restoreErr != nil {
			return errors.New("control: transport checkpoint persistence requires investigation")
		}
		return err
	}
	return nil
}

// PrepareTransportTail requires the caller's exclusive node directory lease.
// It keeps the drained process alive until its counters are durably saved,
// then waits for controller acknowledgement before StopPreparedTransport.
// A stop/write/HTTP failure retains the same checkpoint and counter generation.
// No normal startup may silently restart this worker while it is prepared.
func (r *NativeRuntime) PrepareTransportTail(ctx context.Context) (TransportTail, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	refused := errors.New("control: native transport preparation not confirmed")
	driver, ok := r.Driver.(*NativeEntryDriver)
	if !ok {
		return TransportTail{}, refused
	}
	state, err := r.journal()
	if err != nil || state.Phase != "ready" || state.Retired || state.Current == nil || state.Current.Entry == nil || r.verifyConfig(*state.Current) != nil {
		return TransportTail{}, refused
	}
	path := filepath.Join(r.Directory, "transport-prepared.json")
	var saved transportPreparation
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 3*maxMessage {
			return TransportTail{}, refused
		}
		raw, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Binding != driver.Binding() || saved.Desired.Validate() != nil || saved.Desired.ConfigSHA256 != state.Current.ConfigSHA256 || saved.Desired.Revision != state.Current.Revision || saved.Tail.validate(*state.Current) != nil {
			return TransportTail{}, refused
		}
		process, err := inspectNativeEntry(ctx, driver.SystemdDriver)
		if err != nil {
			return TransportTail{}, refused
		}
		if process.Active {
			// A retry may finish a previously interrupted stop, but cannot use
			// a sample from a different generation or a worker serving traffic.
			if process.StartedAt != saved.Tail.Traffic.StartedAt {
				// A failed activation may have restored this exact old config in
				// a new process. Read its real counters; never refresh a timestamp
				// on the stopped process's old sample.
				if saved.Acknowledged || driver.verifyTransportFence(ctx, saved.Desired) != nil {
					return TransportTail{}, refused
				}
				sample, err := driver.drainTransport(ctx, saved.Desired)
				if err != nil {
					return TransportTail{}, err
				}
				archive := fmt.Sprintf("transport-tail-%d.json", saved.Tail.Traffic.SampledAt.UnixNano())
				if err := replacePrivate(r.Directory, archive, raw); err != nil {
					return TransportTail{}, err
				}
				saved.Tail.Traffic = sample
				updated, err := json.Marshal(saved)
				if err != nil {
					return TransportTail{}, err
				}
				if err := replacePrivate(r.Directory, "transport-prepared.json", updated); err != nil {
					return TransportTail{}, err
				}
			}
			if err := driver.confirmDrainedTransport(ctx, saved.Desired, saved.Tail.Traffic); err != nil {
				return TransportTail{}, err
			}
		}
		return saved.Tail, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return TransportTail{}, err
	}
	if err := r.backup(*state.Current); err != nil {
		return TransportTail{}, err
	}
	sample, err := driver.drainTransport(ctx, *state.Current)
	if err != nil {
		return TransportTail{}, err
	}
	// No sockets remain and the proxy listeners have been removed. Install
	// exclusion now, before any candidate can start accepting client bytes.
	fence, err := driver.transportFence(*state.Current)
	if err != nil {
		return TransportTail{}, err
	}
	if err := fence.Install(ctx); err != nil {
		return TransportTail{}, err
	}
	saved = transportPreparation{Binding: driver.Binding(), Desired: state.Current.clone(), Tail: TransportTail{Revision: state.Current.Revision, ConfigSHA256: state.Current.ConfigSHA256, Traffic: sample}}
	raw, err := json.Marshal(saved)
	if err != nil {
		return TransportTail{}, err
	}
	if err := replacePrivate(r.Directory, "transport-prepared.json", raw); err != nil {
		// Do not restart/reset a still-drained core after storage failure.
		return TransportTail{}, errors.New("control: final counters not persisted; drained worker retained for recovery")
	}
	return saved.Tail, nil
}

// Stop only after the authenticated controller has committed the final sample.
func (r *NativeRuntime) StopPreparedTransport(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	saved, _, err := r.transportPreparation()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if saved.Acknowledged || saved.Tail.Traffic.SampledAt.After(now) || now.Sub(saved.Tail.Traffic.SampledAt) > time.Minute {
		return errors.New("control: final sample expired; stop aborted")
	}
	driver, ok := r.Driver.(*NativeEntryDriver)
	if !ok {
		return errors.New("control: native transport required")
	}
	if err := driver.verifyTransportFence(ctx, saved.Desired); err != nil {
		return err
	}
	process, err := inspectNativeEntry(ctx, driver.SystemdDriver)
	if err != nil {
		return err
	}
	if !process.Active {
		return nil
	}
	if err := driver.confirmDrainedTransport(ctx, saved.Desired, saved.Tail.Traffic); err != nil {
		return err
	}
	return driver.Stop(ctx, saved.Desired)
}
