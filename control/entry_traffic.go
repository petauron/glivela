package control

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"
)

// EntryTraffic is a cumulative sample from the assigned core, not an Agent
// task. A failed sample is omitted and must never reset previous usage.
type EntryTraffic struct {
	StartedAt string                    `json:"startedAt"`
	SampledAt time.Time                 `json:"sampledAt"`
	Counters  map[string]TrafficCounter `json:"counters"`
}

type TrafficCounter struct {
	Upload   int64 `json:"upload,string"`
	Download int64 `json:"download,string"`
}

func (d *EntryDriver) traffic(ctx context.Context, desired Desired) (*EntryTraffic, error) {
	before, err := d.inspect(ctx, desired)
	if err != nil || !before.State.Running || before.State.Restarting || before.State.Pid <= 0 {
		return nil, errors.New("control: entry traffic source unavailable")
	}
	// Use the already installed official CLI rather than a new gRPC dependency.
	// Never reset core counters: retrying a report cannot consume the sample.
	raw, err := d.command(ctx, "container", "exec", d.Container.ContainerID,
		"/usr/local/bin/xray", "api", "statsquery", "--server=127.0.0.1:10085")
	if err != nil {
		return nil, err
	}
	sample, err := parseEntryTraffic(raw, desired, before.State.StartedAt)
	if err != nil {
		return nil, err
	}
	after, err := d.inspect(ctx, desired)
	if err != nil || !after.State.Running || after.State.Restarting || after.State.Pid != before.State.Pid || after.State.StartedAt != before.State.StartedAt {
		return nil, errors.New("control: entry restarted during traffic sampling")
	}
	return sample, nil
}

func parseEntryTraffic(raw []byte, desired Desired, startedAt string) (*EntryTraffic, error) {
	var result struct {
		Stat []struct {
			Name  string      `json:"name"`
			Value json.Number `json:"value"`
		} `json:"stat"`
	}
	if desired.Entry == nil || len(raw) > 1<<20 || json.Unmarshal(raw, &result) != nil || len(result.Stat) > 32768 {
		return nil, errors.New("control: invalid entry traffic response")
	}
	sample := &EntryTraffic{StartedAt: startedAt, SampledAt: time.Now().UTC(), Counters: map[string]TrafficCounter{}}
	users := map[string]string{}
	for _, material := range desired.Entry.Credentials {
		users[material.Credential.User] = material.Credential.ID
		sample.Counters[material.Credential.ID] = TrafficCounter{}
	}
	seen := map[string]bool{}
	for _, stat := range result.Stat {
		parts := strings.Split(stat.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			continue
		}
		id, known := users[parts[1]]
		var value int64
		var err error
		if stat.Value != "" { // Proto3 JSON may omit a zero-valued field.
			value, err = stat.Value.Int64()
		}
		if !known || err != nil || value < 0 || seen[stat.Name] || parts[3] != "uplink" && parts[3] != "downlink" {
			return nil, errors.New("control: entry traffic differs from assigned credentials")
		}
		seen[stat.Name] = true
		counter := sample.Counters[id]
		if parts[3] == "uplink" {
			counter.Upload = value
		} else {
			counter.Download = value
		}
		sample.Counters[id] = counter
	}
	return sample, nil
}

func validateEntryTraffic(desired Desired, sample *EntryTraffic) error {
	if sample == nil {
		return nil
	}
	started, err := time.Parse(time.RFC3339Nano, sample.StartedAt)
	if err != nil || started.IsZero() || sample.SampledAt.IsZero() || started.After(sample.SampledAt) || desired.Entry == nil || len(sample.Counters) != len(desired.Entry.Credentials) {
		return errors.New("control: invalid entry traffic sample")
	}
	for _, material := range desired.Entry.Credentials {
		counter, found := sample.Counters[material.Credential.ID]
		if !found || counter.Upload < 0 || counter.Download < 0 {
			return errors.New("control: incomplete entry traffic inventory")
		}
	}
	return nil
}

func (sample *EntryTraffic) clone() *EntryTraffic {
	if sample == nil {
		return nil
	}
	copy := *sample
	copy.Counters = maps.Clone(sample.Counters)
	return &copy
}
