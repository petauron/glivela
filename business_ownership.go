package glivela

import (
	"errors"
	"time"
)

// BusinessOwnership is sealed with the business data by the one-time offline
// handover tool after it verifies the final backup and stopped old writer.
// It records data authority, never current process/route health. The previous
// writer identity is opaque to the controller, not a host capability contract.
type BusinessOwnership struct {
	SourceSHA256     string `json:"sourceSha256"`
	CaptureSHA256    string `json:"captureSha256"`
	PreviousWriterID string `json:"previousWriterId"`
	StoppedAt        string `json:"stoppedAt"`
	CapturedAt       string `json:"capturedAt"`
}

func (o BusinessOwnership) Validate(sourceSHA256 string) error {
	stop, err := time.Parse(time.RFC3339Nano, o.StoppedAt)
	captured, captureErr := time.Parse(time.RFC3339Nano, o.CapturedAt)
	if !ValidIdentity(sourceSHA256) || o.SourceSHA256 != sourceSHA256 || !ValidIdentity(o.CaptureSHA256) || !ValidIdentity(o.PreviousWriterID) || err != nil || captureErr != nil || stop.IsZero() || captured.Before(stop) || len(o.StoppedAt) > 64 || len(o.CapturedAt) > 64 {
		return errors.New("glivela: invalid final business ownership evidence")
	}
	return nil
}
