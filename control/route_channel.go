package control

import (
	"context"
	"errors"
	pb "github.com/petauron/glivela/internal/controlpb"
)

type routeRepository interface {
	RouteExchange(context.Context, string, *RouteProbeResult) ([]RouteProbe, error)
}
type routeExchange struct {
	Report *RouteProbeResult `json:"report,omitempty"`
}
type routeAssignments struct {
	Checks []RouteProbe `json:"checks"`
}

func (c *Client) RouteExchange(ctx context.Context, report *RouteProbeResult) ([]RouteProbe, error) {
	var result routeAssignments
	if err := c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).RouteChecks, routeExchange{Report: report}, &result, 16<<10, maxMessage); err != nil {
		return nil, err
	}
	for _, p := range result.Checks {
		if p.Validate() != nil {
			return nil, errors.New("control: invalid route assignment")
		}
	}
	return result.Checks, nil
}
