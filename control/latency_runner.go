package control

import (
	"context"
	"net"
	"strconv"
	"time"
)

// A diagnostic step only opens and closes three TCP connections. No core,
// payload, DNS resolver, firewall or runtime reconciliation is involved.
func measureRouteLatency(ctx context.Context, client LatencyClient) error {
	probe, err := client.LatencyExchange(ctx, nil)
	if err != nil || probe == nil {
		return err
	}
	if err := probe.Validate(); err != nil {
		return err
	}
	result := LatencyResult{AttemptID: probe.AttemptID}
	total := 0.0
	for i := 0; i < 3; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(probe.Address, strconv.Itoa(probe.Port)))
		if err == nil {
			total += float64(time.Since(start)) / float64(time.Millisecond)
			result.Samples++
			_ = conn.Close()
		}
	}
	if result.Samples > 0 {
		value := total / float64(result.Samples)
		result.LatencyMillis = &value
	}
	// Reports acknowledge only this attempt; fetch another next iteration.
	_, err = client.LatencyExchange(ctx, &result)
	return err
}
