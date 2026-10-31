package main

import (
	"encoding/json"
	"errors"
	"time"

	glivela "github.com/petauron/glivela"
)

// Center's pilot watermarks are lifetime totals, not physical Xray counters.
// Preserve accounting totals/baselines while binding future deltas to the
// separately retained process sample. Full checkpoints stay in RetainedSource.
func importPilotWatermarks(a archive, m *glivela.ImportMaterial, credentials map[string]glivela.Credential) error {
	rows, err := records(a, "glivela_pilot_checkpoint")
	if err != nil {
		return err
	}
	endpoints, err := records(a, "meridian_endpoints")
	if err != nil {
		return err
	}
	entries := map[string]string{}
	for _, r := range endpoints {
		id, entry := r.text("id"), r.text("application_id")
		if r.err != nil {
			return r.err
		}
		entries[id] = entry
	}
	seenEntries := map[string]bool{}
	for _, r := range rows {
		var checkpoint struct {
			EntryID              string
			StartedAt, SampledAt time.Time
			Raw, Totals          []glivela.CounterSnapshot
		}
		endpoint := r.text("endpoint_id")
		raw := r.jsonBytes("checkpoint_json")
		invalid := errors.New("invalid pilot traffic checkpoint")
		if r.err != nil || json.Unmarshal(raw, &checkpoint) != nil || entries[endpoint] == "" || entries[endpoint] != checkpoint.EntryID || seenEntries[checkpoint.EntryID] || checkpoint.StartedAt.IsZero() || checkpoint.SampledAt.Before(checkpoint.StartedAt) || len(checkpoint.Raw) == 0 || len(checkpoint.Raw) != len(checkpoint.Totals) {
			return invalid
		}
		seenEntries[checkpoint.EntryID] = true
		physical := map[string]glivela.CounterSnapshot{}
		for _, c := range checkpoint.Raw {
			if _, duplicate := physical[c.CredentialID]; duplicate || c.UpBytes < 0 || c.DownBytes < 0 {
				return invalid
			}
			physical[c.CredentialID] = c
		}
		seen := map[string]bool{}
		for _, total := range checkpoint.Totals {
			c, exists := credentials[total.CredentialID]
			sample, sampled := physical[total.CredentialID]
			counter, retained := m.TrafficCounters[total.CredentialID]
			if !exists || c.EntryID != checkpoint.EntryID || !sampled || !retained || seen[total.CredentialID] || total.UpBytes < sample.UpBytes || total.DownBytes < sample.DownBytes || counter.RawUploadBytes != total.UpBytes || counter.RawDownloadBytes != total.DownBytes {
				return invalid
			}
			seen[total.CredentialID] = true
			counter.RawUploadBytes, counter.RawDownloadBytes = sample.UpBytes, sample.DownBytes
			counter.StartedAt = checkpoint.StartedAt.Format(time.RFC3339Nano)
			counter.ObservedAt = checkpoint.SampledAt.Format(time.RFC3339Nano)
			m.TrafficCounters[total.CredentialID] = counter
		}
		for id, c := range credentials {
			if c.EntryID == checkpoint.EntryID && !seen[id] {
				return invalid
			}
		}
	}
	for _, entry := range entries {
		if a.References.Applications[entry].Runtime == "host" && !seenEntries[entry] {
			return errors.New("native entry pilot checkpoint missing")
		}
	}
	return nil
}
