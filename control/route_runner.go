package control

import (
	"context"
	"errors"
	"time"
)

type RouteClient interface {
	RouteExchange(context.Context, *RouteProbeResult) ([]RouteProbe, error)
}

// RouteRunner runs on the entry. It never starts, stops or configures a proxy.
// Fetch before every check: if the previous report committed but its response
// was lost, the completed attempt is no longer offered and is not rerun.
type RouteRunner struct {
	Client RouteClient
	probe  func(context.Context, RouteProbe) (RouteProbeResult, error)
}

func (r RouteRunner) Step(ctx context.Context) error {
	if r.Client == nil {
		return errors.New("control: route client required")
	}
	checks, err := r.Client.RouteExchange(ctx, nil)
	if err != nil {
		return err
	}
	if len(checks) == 0 {
		return nil
	}
	// One bounded check per iteration avoids concurrent probes on small nodes.
	p := checks[0]
	if err := p.Validate(); err != nil {
		return err
	}
	probe := r.probe
	if probe == nil {
		probe = CheckRoute
	}
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	result, probeErr := probe(checkCtx, p)
	cancel()
	if err := validateRouteResult(p, result); err != nil {
		return err
	}
	if probeErr != nil && result.Passed {
		return errors.New("control: contradictory route result")
	}
	_, err = r.Client.RouteExchange(ctx, &result)
	if err != nil {
		return err
	}
	return probeErr
}

func (r RouteRunner) Run(ctx context.Context, interval time.Duration, result func(error)) error {
	if interval < time.Second || interval > time.Minute {
		return errors.New("control: invalid route poll interval")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		step, cancel := context.WithTimeout(ctx, 45*time.Second)
		err := r.Step(step)
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
