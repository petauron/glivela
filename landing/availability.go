package landing

import "time"

const (
	FailureThreshold  = 3
	RecoveryThreshold = 2
	// Business evidence is never renewed indefinitely by successful identity
	// checks. Three bounded rounds fit within this independent freshness bound.
	BusinessLifetime = 45 * time.Second
)

// NetworkFailure is only emitted after the caller has separately verified
// identity and runtime configuration. Unknown errors remain fail-closed.
type NetworkFailure struct{ Stage string }

func (e *NetworkFailure) Error() string { return "landing: network probe failed at " + e.Stage }

type availability struct {
	up        bool
	failures  int
	successes int
}

func (a *availability) observe(success, networkFailure bool) bool {
	if success {
		a.failures = 0
		if a.successes < RecoveryThreshold {
			a.successes++
		}
		if a.successes == RecoveryThreshold {
			a.up = true
		}
	} else if networkFailure {
		a.successes = 0
		if a.failures < FailureThreshold {
			a.failures++
		}
		if a.failures == FailureThreshold {
			a.up = false
		}
	} else {
		*a = availability{}
	}
	return a.up
}
