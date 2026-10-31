package control

import (
	"context"
	"time"
)

// One independent serialized loop per native node. Diagnostics are minute
// based; commands use the existing authenticated channel, not a host shell API.
func RunNetworkOptimization(ctx context.Context, client *Client, directory string) {
	step, stop := context.WithTimeout(ctx, 20*time.Second)
	resumeNetwork(step, directory)
	stop()
	var report *NetworkReport
	last := time.Time{}
	for ctx.Err() == nil {
		step, stop := context.WithTimeout(ctx, 30*time.Second)
		if report == nil && time.Since(last) >= time.Minute {
			report = &NetworkReport{Snapshot: inspectNetwork(step, directory)}
			last = time.Now()
		}
		if report != nil && time.Since(report.Snapshot.CheckedAt) > time.Minute {
			report.Snapshot = inspectNetwork(step, directory)
			last = time.Now()
		}
		command, err := client.networkExchange(step, report)
		if err == nil {
			report = nil
			if command != nil {
				value := executeNetwork(step, directory, *command)
				report = &value
				last = time.Now()
				stop()
				continue // send the actual result immediately
			}
		}
		stop()
		// Normal observations stay minute-based. Retry an unconfirmed report
		// briefly, while connected watches wake new commands immediately.
		delay := time.Until(last.Add(time.Minute))
		if err != nil || report != nil {
			delay = 5 * time.Second
		}
		if delay < time.Second {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-client.nodeSignal(nodeSignalNetwork):
			timer.Stop()
		}
	}
}
