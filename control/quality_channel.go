package control

import (
	"context"
	"errors"
	pb "github.com/petauron/glivela/internal/controlpb"
	"github.com/petauron/glivela/ipquality"
	"time"
)

type QualityAssignment struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Revision  uint64    `json:"revision"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type qualityReport struct {
	ID     string           `json:"id"`
	Result ipquality.Result `json:"result"`
}
type qualityMessage struct {
	Report     *qualityReport     `json:"report,omitempty"`
	Assignment *QualityAssignment `json:"assignment,omitempty"`
}

func (c *Client) qualityExchange(ctx context.Context, report *qualityReport) (*QualityAssignment, error) {
	var out qualityMessage
	if err := c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).IPQuality, qualityMessage{Report: report}, &out, 128<<10, 4096); err != nil {
		return nil, err
	}
	if a := out.Assignment; a != nil && (!speedID(a.ID) || !qualityPublic(a.Address) || a.Revision == 0 || time.Until(a.ExpiresAt) <= 0 || time.Until(a.ExpiresAt) > 5*time.Minute) {
		return nil, errors.New("invalid quality assignment")
	}
	return out.Assignment, nil
}

// Normal health frequency remains unchanged; explicit assignments wake immediately.
func RunIPQuality(ctx context.Context, client *Client) {
	var pending *qualityReport
	for ctx.Err() == nil {
		step, cancel := context.WithTimeout(ctx, 20*time.Second)
		a, err := client.qualityExchange(step, pending)
		cancel()
		if err == nil {
			pending = nil
			if a != nil {
				result := executeQuality(ctx, *a)
				pending = &qualityReport{a.ID, result}
				continue
			}
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-client.nodeSignal(nodeSignalQuality):
			timer.Stop()
		}
	}
}
