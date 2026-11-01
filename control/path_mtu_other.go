//go:build !linux

package control

import "context"

func observePathMTUs(context.Context, string) []PathMTUObservation { return nil }
func resumePathMTUs(context.Context, string, Desired)              {}
func executePathMTU(ctx context.Context, directory string, c NetworkCommand) NetworkReport {
	r := pathNetworkReport(ctx, directory)
	r.Result = &NetworkResult{ID: c.ID, State: "failed", Message: "路径 MTU 仅支持原生 Linux 节点"}
	return r
}
