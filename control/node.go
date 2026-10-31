package control

import (
	"context"
	"errors"
	"os"
	"time"

	glivela "github.com/petauron/glivela"
)

// Runtime is Glivela-owned, not a host/Agent RPC. Apply must persist intent,
// validate a candidate and restore the prior runtime if activation fails.
// Inspect must check actual runtime state, not merely return its last receipt.
type Runtime interface {
	Apply(context.Context, Desired) error
	Inspect(context.Context) (Observation, error)
}

type ExchangeClient interface {
	Exchange(context.Context, *Observation) (Desired, error)
}

type NodeRunner struct {
	Client  ExchangeClient
	Runtime Runtime
}

// Startup acceptance includes network, service and route checks. Give only
// that recovery path enough time to finish without extending normal polling.
func (n NodeRunner) StepTimeout() time.Duration {
	if pending, ok := n.Runtime.(interface{ startupRecoveryPending() bool }); ok && pending.startupRecoveryPending() {
		return 90 * time.Second
	}
	return 30 * time.Second
}

func (n NodeRunner) Step(ctx context.Context) error {
	if n.Client == nil || n.Runtime == nil {
		return errors.New("control: node is not configured")
	}
	current, err := n.Runtime.Inspect(ctx)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("control: cannot establish current runtime state")
	}
	var report *Observation
	if err == nil {
		report = &current
	}
	desired, err := n.Client.Exchange(ctx, report)
	if err != nil {
		return err
	} // An offline controller never stops the runtime.
	if desired.Validate() != nil {
		return errors.New("control: invalid desired state")
	}
	if report != nil {
		if desired.Revision < current.Revision || desired.Revision == current.Revision && desired.ConfigSHA256 != current.ConfigSHA256 {
			return errors.New("control: controller attempted revision rollback or reuse")
		}
		if glivela.VerifyAppliedReceipt(desired.DesiredArtifact, current.AppliedReceipt) == nil {
			return nil
		}
		// Only an explicitly stopped startup may retry the same authenticated
		// assignment. Ordinary later health loss still requires investigation.
		if desired.Revision == current.Revision {
			if retry, ok := n.Runtime.(interface {
				retryStartup(context.Context, Desired) (bool, bool, error)
			}); ok {
				handled, recovered, err := retry.retryStartup(ctx, desired)
				if err != nil {
					return err
				}
				if handled {
					if !recovered {
						return nil
					}
					return n.reportApplied(ctx, desired)
				}
			}
			return errors.New("control: runtime requires investigation")
		}
	}
	if err := n.Runtime.Apply(ctx, desired); err != nil {
		return err
	}
	return n.reportApplied(ctx, desired)
}

func (n NodeRunner) reportApplied(ctx context.Context, desired Desired) error {
	actual, err := n.Runtime.Inspect(ctx)
	if err != nil || glivela.VerifyAppliedReceipt(desired.DesiredArtifact, actual.AppliedReceipt) != nil {
		return errors.New("control: runtime acceptance failed")
	}
	// Report independently observed state. If the control connection fails,
	// the next poll reconciles it rather than applying the revision again.
	_, err = n.Client.Exchange(ctx, &actual)
	return err
}

// Changed wakes on a newer authenticated desired revision.
func (n NodeRunner) Changed() <-chan struct{} {
	if c, ok := n.Client.(*Client); ok {
		return c.nodeSignal(nodeSignalDesired)
	}
	return nil
}

// Run bounds polling and retries. Per-step timeouts also bound a malfunctioning
// runtime probe. Failure never results in a tight restart/reconnect loop.
func (n NodeRunner) Run(ctx context.Context, interval time.Duration, result func(error)) error {
	if interval < time.Second || interval > time.Minute {
		return errors.New("control: invalid poll interval")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		step, cancel := context.WithTimeout(ctx, n.StepTimeout())
		err := n.Step(step)
		cancel()
		if result != nil {
			result(err)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		case <-n.Changed():
			timer.Stop()
		}
	}
}
