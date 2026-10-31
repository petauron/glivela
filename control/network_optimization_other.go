//go:build !linux

package control

import (
	"context"
	"time"
)

func inspectNetwork(context.Context, string) NetworkSnapshot {
	v := NetworkSnapshot{CheckedAt: time.Now().UTC(), Scope: "unsupported", Reason: "仅支持原生 Linux 节点"}
	v.Fingerprint = networkDigest(v)
	return v
}
func executeNetwork(ctx context.Context, directory string, c NetworkCommand) NetworkReport {
	return NetworkReport{Snapshot: inspectNetwork(ctx, directory), Result: &NetworkResult{ID: c.ID, State: "failed", Message: "仅支持原生 Linux 节点"}}
}
func resumeNetwork(context.Context, string) {}
