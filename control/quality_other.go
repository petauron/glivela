//go:build !linux

package control

import (
	"context"
	"github.com/petauron/glivela/ipquality"
)

func executeQuality(context.Context, QualityAssignment) ipquality.Result {
	return ipquality.Result{Error: "docker_unavailable"}
}
