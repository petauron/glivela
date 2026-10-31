//go:build !linux

package control

import "context"

type speedSession struct{}

func newSpeedSession(string, string, string, string, string) *speedSession { return &speedSession{} }
func (*speedSession) close() error                                         { return nil }
func (*speedSession) setProgress(func(string, SpeedPoint))                 {}
func (*speedSession) execute(_ context.Context, p SpeedAssignment) SpeedReport {
	return SpeedReport{ID: p.ID, Role: p.Role, Error: errSpeedUnsupported.Error(), CleanupConfirmed: true}
}

func (*speedSession) recover() error { return nil }
