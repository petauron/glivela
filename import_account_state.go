package glivela

import (
	"errors"
	"time"
)

// Preserve the recorded schedule, not a newly calculated cycle from import
// time. Strings retain the source timestamp's precision and offset verbatim.
type ImportResetSchedule struct {
	NextResetAt string `json:"nextResetAt"`
	LastResetAt string `json:"lastResetAt"`
}

// Directional totals and raw counter watermarks have different meanings from
// the account quota baseline. Neither may be reconstructed from their sum.
type ImportTrafficCounters struct {
	UploadBytes         int64  `json:"uploadBytes"`
	DownloadBytes       int64  `json:"downloadBytes"`
	RawUploadBytes      int64  `json:"rawUploadBytes"`
	RawDownloadBytes    int64  `json:"rawDownloadBytes"`
	StartedAt           string `json:"startedAt"`
	ObservedAt          string `json:"observedAt"`
	WatermarkObservedAt string `json:"watermarkObservedAt"`
}

func validImportTime(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 64 {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func (m ImportMaterial) validateAccountState() error {
	credentials := 0
	if len(m.ResetSchedules) != len(m.Plan.Accounts) {
		return errors.New("glivela: incomplete reset schedule inventory")
	}
	for _, account := range m.Plan.Accounts {
		schedule, exists := m.ResetSchedules[account.Account.ID]
		if !exists || !validImportTime(schedule.NextResetAt) || !validImportTime(schedule.LastResetAt) {
			return errors.New("glivela: missing or invalid reset schedule")
		}
		for _, credential := range account.Credentials {
			credentials++
			counters, exists := m.TrafficCounters[credential.ID]
			if !exists || counters.UploadBytes < 0 || counters.DownloadBytes < 0 || counters.RawUploadBytes < 0 || counters.RawDownloadBytes < 0 || !validImportTime(counters.StartedAt) || !validImportTime(counters.ObservedAt) || !validImportTime(counters.WatermarkObservedAt) {
				return errors.New("glivela: missing or invalid directional traffic counters")
			}
		}
	}
	if len(m.TrafficCounters) != credentials {
		return errors.New("glivela: orphaned directional traffic counters")
	}
	return nil
}
