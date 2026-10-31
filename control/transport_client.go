package control

import (
	"context"
	"errors"
	pb "github.com/petauron/glivela/internal/controlpb"
)

func (c *Client) RecordTransportTail(ctx context.Context, tail TransportTail) error {
	var out struct{}
	return c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).RecordTransportTail, tail, &out, maxMessage, 4096)
}
func (c *Client) TransportCancelIntent(ctx context.Context, tail TransportTail) (Desired, error) {
	var out Desired
	err := c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).CancelTransport, tail, &out, maxMessage, maxMessage)
	if err != nil || out.Validate() != nil {
		return Desired{}, errors.New("control: cancellation not confirmed")
	}
	return out, nil
}
func (c *Client) ResumeTransportPreparation(ctx context.Context, actual Observation) error {
	var out struct{}
	return c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).ResumeTransport, actual, &out, maxMessage, 4096)
}
