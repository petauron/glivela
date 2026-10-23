package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

func (c *Client) RecordTransportTail(ctx context.Context, tail TransportTail) error {
	return c.transportMaintenance(ctx, "/v1/transport-tail", tail)
}

func (c *Client) TransportCancelIntent(ctx context.Context, tail TransportTail) (Desired, error) {
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return Desired{}, err
	}
	u.Path = "/v1/transport-cancel-intent"
	raw, err := json.Marshal(tail)
	if err != nil || len(raw) > maxMessage {
		return Desired{}, errors.New("control: invalid cancellation record")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(raw))
	if err != nil {
		return Desired{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return Desired{}, errors.New("control: cancellation acknowledgement unavailable")
	}
	defer response.Body.Close()
	var desired Desired
	if response.StatusCode != http.StatusOK || decode(io.LimitReader(response.Body, maxMessage+1), &desired) != nil || desired.Validate() != nil {
		return Desired{}, errors.New("control: cancellation not confirmed")
	}
	return desired, nil
}

func (c *Client) ResumeTransportPreparation(ctx context.Context, actual Observation) error {
	return c.transportMaintenance(ctx, "/v1/transport-resume", actual)
}

func (c *Client) transportMaintenance(ctx context.Context, path string, value any) error {
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return errors.New("control: maintenance endpoint unavailable")
	}
	u.Path = path
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxMessage {
		return errors.New("control: maintenance record exceeds bound")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(raw))
	if err != nil {
		return errors.New("control: maintenance request unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("control: maintenance acknowledgement unavailable; retain checkpoint")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusNoContent {
		return errors.New("control: maintenance not acknowledged; retain checkpoint")
	}
	return nil
}
