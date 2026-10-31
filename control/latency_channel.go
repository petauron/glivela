package control

import (
	"context"
	"errors"
	pb "github.com/petauron/glivela/internal/controlpb"
)

type LatencyClient interface {
	LatencyExchange(context.Context, *LatencyResult) (*LatencyProbe, error)
}
type latencyExchange struct {
	Report *LatencyResult `json:"report,omitempty"`
}
type latencyAssignment struct {
	Probe *LatencyProbe `json:"probe"`
}

func (c *Client) LatencyExchange(ctx context.Context, report *LatencyResult) (*LatencyProbe, error) {
	var result latencyAssignment
	if err := c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).RouteLatency, latencyExchange{Report: report}, &result, 4096, 16<<10); err != nil {
		return nil, err
	}
	if result.Probe != nil && result.Probe.Validate() != nil {
		return nil, errors.New("control: invalid latency assignment")
	}
	return result.Probe, nil
}
