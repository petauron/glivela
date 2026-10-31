//go:build linux

package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// drainTransport closes only this worker's proxy listeners using its existing
// API. Established requests must finish; a deadline restores the original
// listeners rather than treating a quiet counter interval as finality.
// The caller holds the node directory lease (the normal node loop is stopped).
func (d *NativeEntryDriver) drainTransport(ctx context.Context, desired Desired) (sample *EntryTraffic, result error) {
	if err := d.readyProcess(ctx, desired); err != nil {
		return nil, err
	}
	if err := verifyExecutableFile(d.Binary, d.BinarySHA256); err != nil {
		return nil, err
	}
	before, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil {
		return nil, err
	}
	var config struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if json.Unmarshal(desired.Config, &config) != nil {
		return nil, errors.New("control: owned inbounds unavailable")
	}
	var tags []string
	var restore []json.RawMessage
	for _, raw := range config.Inbounds {
		var inbound struct {
			Tag string `json:"tag"`
		}
		if json.Unmarshal(raw, &inbound) != nil || inbound.Tag == "" {
			return nil, errors.New("control: invalid owned inbound")
		}
		if inbound.Tag != "api" {
			tags = append(tags, inbound.Tag)
			restore = append(restore, raw)
		}
	}
	if len(tags) == 0 {
		return nil, errors.New("control: proxy inbounds missing")
	}
	// Restore every original proxy listener on an interrupted drain. Existing
	// credentials are reloaded in the SAME process, keeping cumulative counters.
	defer func() {
		if result == nil {
			return
		}
		recovery, cancel := recoveryContext()
		defer cancel()
		for _, tag := range tags {
			_, _ = nativeEntryCommand(recovery, d.Binary, "api", "rmi", "--server=127.0.0.1:10085", tag)
		}
		data, _ := json.Marshal(map[string]any{"inbounds": restore})
		cmd := exec.CommandContext(recovery, d.Binary, "api", "adi", "--server=127.0.0.1:10085")
		cmd.Stdin = bytes.NewReader(data)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		if cmd.Run() != nil || d.readyProcess(recovery, desired) != nil {
			result = errors.New("control: drain interrupted; original listeners require recovery")
		}
	}()
	for _, tag := range tags {
		if _, err := nativeEntryCommand(ctx, d.Binary, "api", "rmi", "--server=127.0.0.1:10085", tag); err != nil {
			return nil, err
		}
	}
	root := filepath.Join("/proc", strconv.Itoa(before.PID))
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var prior *EntryTraffic
	for {
		after, err := inspectNativeEntry(ctx, d.SystemdDriver)
		if err != nil || before != after {
			return nil, errors.New("control: worker generation changed during drain")
		}
		idle, err := transportSocketsDrained(root)
		if err != nil {
			return nil, err
		}
		if idle {
			raw, err := nativeEntryCommand(ctx, d.Binary, "api", "statsquery", "--server=127.0.0.1:10085")
			if err != nil {
				return nil, err
			}
			current, err := parseEntryTraffic(raw, desired, before.StartedAt)
			if err != nil {
				return nil, err
			}
			verified, err := inspectNativeEntry(ctx, d.SystemdDriver)
			if err != nil || verified != before {
				return nil, errors.New("control: final counter generation changed")
			}
			// Socket drainage is mandatory; stable counters alone never suffice.
			if prior != nil && reflect.DeepEqual(prior.Counters, current.Counters) {
				return current, nil
			}
			prior = current
		} else {
			prior = nil
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("control: live requests did not drain; switch refused")
		case <-ticker.C:
		}
	}
}

func transportSocketsDrained(root string) (bool, error) {
	entries, err := os.ReadDir(filepath.Join(root, "fd"))
	if err != nil || len(entries) > 65536 {
		return false, errors.New("control: worker descriptors unavailable")
	}
	owned := map[string]bool{}
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(root, "fd", entry.Name()))
		if err != nil {
			return false, errors.New("control: worker descriptors changed")
		}
		if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			owned[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	for _, network := range []string{"tcp", "tcp6", "udp", "udp6"} {
		file, err := os.Open(filepath.Join(root, "net", network))
		if err != nil {
			return false, errors.New("control: worker socket inventory unavailable")
		}
		idle, err := drainedSocketTable(file, owned, network)
		_ = file.Close()
		if err != nil || !idle {
			return false, err
		}
	}
	return true, nil
}

func (d *NativeEntryDriver) restorePreparedListeners(ctx context.Context, desired Desired, sample *EntryTraffic) error {
	if err := d.verifyTransportFence(ctx, desired); err != nil {
		return err
	}
	if d.readyProcess(ctx, desired) == nil {
		return nil
	}
	before, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil || !before.Active || sample == nil || before.StartedAt != sample.StartedAt {
		return errors.New("control: unacknowledged worker generation unavailable")
	}
	if err := d.confirmDrainedTransport(ctx, desired, sample); err != nil {
		return err
	}
	var config struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if json.Unmarshal(desired.Config, &config) != nil {
		return errors.New("control: saved inbounds invalid")
	}
	var restore []json.RawMessage
	for _, raw := range config.Inbounds {
		var inbound struct {
			Tag string `json:"tag"`
		}
		if json.Unmarshal(raw, &inbound) != nil || inbound.Tag == "" {
			return errors.New("control: saved inbound invalid")
		}
		if inbound.Tag != "api" {
			restore = append(restore, raw)
		}
	}
	data, _ := json.Marshal(map[string]any{"inbounds": restore})
	cmd := exec.CommandContext(ctx, d.Binary, "api", "adi", "--server=127.0.0.1:10085")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if cmd.Run() != nil || d.readyProcess(ctx, desired) != nil {
		return errors.New("control: original listeners not restored")
	}
	after, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil || before != after {
		return errors.New("control: original worker changed during restoration")
	}
	return nil
}

func (d *NativeEntryDriver) confirmDrainedTransport(ctx context.Context, desired Desired, sample *EntryTraffic) error {
	process, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil || !process.Active || process.StartedAt != sample.StartedAt || process.PID <= 0 || verifyExecutableFile(d.Binary, d.BinarySHA256) != nil {
		return errors.New("control: drained worker identity differs")
	}
	idle, err := transportSocketsDrained(filepath.Join("/proc", strconv.Itoa(process.PID)))
	if err != nil || !idle {
		return errors.New("control: worker resumed traffic after final sample")
	}
	raw, err := nativeEntryCommand(ctx, d.Binary, "api", "statsquery", "--server=127.0.0.1:10085")
	if err != nil {
		return err
	}
	current, err := parseEntryTraffic(raw, desired, process.StartedAt)
	if err != nil || !reflect.DeepEqual(current.Counters, sample.Counters) {
		return errors.New("control: sealed counters changed")
	}
	after, err := inspectNativeEntry(ctx, d.SystemdDriver)
	if err != nil || process != after {
		return errors.New("control: drained generation changed")
	}
	return nil
}

func drainedSocketTable(reader io.Reader, owned map[string]bool, network string) (bool, error) {
	limited := &io.LimitedReader{R: reader, N: 16<<20 + 1}
	scanner := bufio.NewScanner(limited)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && fields[0] == "sl" {
			continue
		}
		if len(fields) < 10 {
			return false, errors.New("control: malformed socket inventory")
		}
		if !owned[fields[9]] {
			continue
		}
		// Only the original IPv4 loopback API listener may remain. An accepted
		// API request must finish too before the next final sample is taken.
		if network == "tcp" && fields[1] == "0100007F:2765" && fields[3] == "0A" {
			continue
		}
		return false, nil
	}
	if scanner.Err() != nil || limited.N == 0 {
		return false, errors.New("control: bounded socket inventory failed")
	}
	return true, nil
}
