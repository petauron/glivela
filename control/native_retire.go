package control

import (
	"context"
	"errors"
)

// Retire runs under the stopped node's directory lease. It preserves the
// configuration, identity and history, but durably forbids automatic restart.
// Only the concrete app-owned native drivers are supported, not host commands.
func (r *NativeRuntime) Retire(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state, err := r.journal()
	if err != nil || state.Phase != "ready" || state.Current == nil {
		return errors.New("control: complete runtime recovery before retirement")
	}
	var installed SystemdDriver
	switch driver := r.Driver.(type) {
	case SystemdDriver:
		if state.Current.Landing == nil || state.Current.Entry != nil {
			return errors.New("control: native retirement role differs")
		}
		installed = driver
	case *NativeEntryDriver:
		if err := driver.plan(*state.Current); err != nil {
			return err
		}
		installed = driver.SystemdDriver
	default:
		return errors.New("control: native installed worker required")
	}
	if err := installed.verifyLoadedService(ctx); err != nil {
		return err
	}
	if err := r.verifyConfig(*state.Current); err != nil {
		return err
	}
	if err := r.backup(*state.Current); err != nil {
		return err
	}
	// A crash or failed stop leaves this intent in place. Retry this command;
	// neither startup recovery nor a controller desired message may undo it.
	state.Retired = true
	if err := r.save(state); err != nil {
		return err
	}
	if err := r.Driver.Stop(ctx, *state.Current); err != nil {
		return err
	}
	if entry, ok := r.Driver.(*NativeEntryDriver); ok {
		gates, err := entry.gates(*state.Current)
		if err != nil {
			return err
		}
		for _, gate := range gates {
			if err := gate.Remove(ctx); err != nil {
				return err
			}
		}
		policy, err := entry.policy(*state.Current)
		if err != nil {
			return err
		}
		return policy.Remove(ctx)
	}
	return nil
}
