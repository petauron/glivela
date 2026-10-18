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
	Inspect(context.Context) (glivela.AppliedReceipt, error)
}

type ExchangeClient interface {
	Exchange(context.Context, *glivela.AppliedReceipt) (Desired, error)
}

type NodeRunner struct {
	Client  ExchangeClient
	Runtime Runtime
}

func (n NodeRunner) Step(ctx context.Context) error {
	if n.Client == nil || n.Runtime == nil {
		return errors.New("control: node is not configured")
	}
	current, err := n.Runtime.Inspect(ctx)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("control: cannot establish current runtime state")
	}
	var report *glivela.AppliedReceipt
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
		if glivela.VerifyAppliedReceipt(desired.DesiredArtifact, current) == nil {
			return nil
		}
		// Health loss alone does not authorize restarting the same revision.
		if desired.Revision == current.Revision {
			return errors.New("control: runtime requires investigation")
		}
	}
	if err := n.Runtime.Apply(ctx, desired); err != nil {
		return err
	}
	actual, err := n.Runtime.Inspect(ctx)
	if err != nil || glivela.VerifyAppliedReceipt(desired.DesiredArtifact, actual) != nil {
		return errors.New("control: runtime acceptance failed")
	}
	// Report independently observed state. If the control connection fails,
	// the next poll reconciles it rather than applying the revision again.
	_, err = n.Client.Exchange(ctx, &actual)
	return err
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
		step, cancel := context.WithTimeout(ctx, 30*time.Second)
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
		}
	}
}
