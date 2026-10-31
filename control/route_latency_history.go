package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

const (
	latencyHistoryLimit       = 20
	latencyHistoryTargetLimit = 512
)

// Historical diagnostics are display-only; they are never restored as an
// issued probe, current runtime health, or route admission evidence.
type latencyHistoryRecord struct {
	AddressHash string          `json:"addressHash"`
	Samples     []LatencySample `json:"samples"`
}
type latencyHistoryState struct {
	Version int                             `json:"version"`
	Targets map[string]latencyHistoryRecord `json:"targets"`
}

func latencyAddressHash(t latencyTarget) string {
	hash := sha256.Sum256([]byte(t.Address))
	return hex.EncodeToString(hash[:])
}

func (h latencyHistoryState) validate() error {
	if h.Version != 1 || h.Targets == nil || len(h.Targets) > latencyHistoryTargetLimit {
		return errors.New("invalid latency history")
	}
	for key, record := range h.Targets {
		parts := strings.Split(key, "/")
		if len(parts) != 3 || !glivela.ValidIdentifier(parts[0]) || !glivela.ValidIdentifier(parts[1]) || !glivela.ValidIdentity(record.AddressHash) || len(record.Samples) == 0 || len(record.Samples) > latencyHistoryLimit {
			return errors.New("invalid latency history target")
		}
		port, err := strconv.Atoi(parts[2])
		if err != nil || strconv.Itoa(port) != parts[2] || port != landing.SOCKSPort && (port < 24000 || port > 24999) {
			return errors.New("invalid latency history port")
		}
		for _, sample := range record.Samples {
			if sample.CheckedAt.IsZero() || sample.Samples < 0 || sample.Samples > 3 || (sample.Samples == 0) != (sample.LatencyMillis == nil) {
				return errors.New("invalid latency history sample")
			}
			if sample.LatencyMillis != nil {
				value := *sample.LatencyMillis
				if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 3000 {
					return errors.New("invalid latency history value")
				}
			}
		}
	}
	return nil
}

func (s *Store) loadLatencyHistoryLocked() {
	if s.latencyHistory != nil {
		return
	}
	s.latencyHistory = &latencyHistoryState{Version: 1, Targets: map[string]latencyHistoryRecord{}}
	if !filepath.IsAbs(s.path) {
		s.latencyHistoryFault = true
		return
	}
	var saved latencyHistoryState
	err := readControlState(filepath.Join(filepath.Dir(s.path), "route-latency-history.json"), &saved)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		err = saved.validate()
	}
	if err != nil {
		// This cache is non-authoritative. Preserve an unsafe or corrupt file for
		// diagnosis instead of blocking controller startup or overwriting it.
		s.latencyHistoryFault = true
		log.Printf("Glivela TCP latency history unavailable; using in-memory samples: %v", err)
		return
	}
	s.latencyHistory = &saved
}

func (s *Store) recentLatencyHistoryLocked(key string, target latencyTarget) []LatencySample {
	s.loadLatencyHistoryLocked()
	record, ok := s.latencyHistory.Targets[key]
	if !ok || record.AddressHash != latencyAddressHash(target) {
		return nil
	}
	return append([]LatencySample(nil), record.Samples...)
}

func (s *Store) saveLatencyHistoryLocked(key string, target latencyTarget, samples []LatencySample) {
	s.loadLatencyHistoryLocked()
	if len(samples) > latencyHistoryLimit {
		samples = samples[len(samples)-latencyHistoryLimit:]
	}
	s.latencyHistory.Targets[key] = latencyHistoryRecord{AddressHash: latencyAddressHash(target), Samples: append([]LatencySample(nil), samples...)}
	if len(s.latencyHistory.Targets) > latencyHistoryTargetLimit {
		oldestKey := ""
		var oldest time.Time
		for other, record := range s.latencyHistory.Targets {
			if other == key {
				continue
			}
			at := record.Samples[len(record.Samples)-1].CheckedAt
			if oldestKey == "" || at.Before(oldest) || at.Equal(oldest) && other < oldestKey {
				oldestKey, oldest = other, at
			}
		}
		delete(s.latencyHistory.Targets, oldestKey)
	}
	if s.latencyHistoryFault {
		return
	}
	if err := writeControlState(filepath.Join(filepath.Dir(s.path), "route-latency-history.json"), *s.latencyHistory); err != nil {
		// Atomic replacement can fail after rename. Stop further disk writes until
		// restart, while keeping live diagnostics and business control available.
		s.latencyHistoryFault = true
		log.Printf("Glivela TCP latency history could not be saved; retaining in-memory samples: %v", err)
	}
}
