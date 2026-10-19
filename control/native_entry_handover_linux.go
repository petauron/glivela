//go:build linux

package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
)

// StageNativeEntryHandover initializes only an unused, installer-owned native
// node from an explicitly stopped legacy source. It does not install services,
// change platform records or public bindings, start a worker, or claim health.
// Old resources and their original configuration remain available for recovery.
func StageNativeEntryHandover(ctx context.Context, checkpoint string, driver *NativeEntryDriver, desired Desired) error {
	invalid := errors.New("control: stopped legacy entry and unused owned native installation required")
	if os.Geteuid() != 0 || driver == nil || !filepath.IsAbs(checkpoint) || filepath.Clean(checkpoint) != checkpoint || filepath.Base(checkpoint) != "snapshot.json" || driver.plan(desired) != nil {
		return invalid
	}
	if err := rootEntryCheckpointDirectory(filepath.Dir(checkpoint)); err != nil {
		return err
	}
	if err := rootEntryCheckpointDirectory(driver.Directory); err != nil {
		return err
	}
	if entryPathsOverlap(driver.Directory, filepath.Dir(checkpoint)) {
		return invalid
	}
	unlock, err := LockDirectory(filepath.Dir(checkpoint))
	if err != nil {
		return err
	}
	defer unlock()
	unseat, err := LockDirectory(driver.Directory)
	if err != nil {
		return err
	}
	defer unseat()
	info, err := os.Lstat(checkpoint)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2*maxMessage {
		return invalid
	}
	if uid, err := entryFileUID(info); err != nil || uid != 0 {
		return invalid
	}
	raw, err := os.ReadFile(checkpoint)
	if err != nil {
		return err
	}
	var saved legacyEntrySnapshot
	id, identityErr := entryPlanIdentity(*desired.Entry)
	if decode(bytes.NewReader(raw), &saved) != nil || saved.Version != 1 || identityErr != nil || saved.ApplicationID != id || !exactDockerID(saved.Container.ID) {
		return invalid
	}
	if err := retainLegacyEntryIdentities(saved.Configuration, desired.Config); err != nil {
		return err
	}
	verifySource := func() error {
		if err := requireLegacyWriterStopped(ctx); err != nil {
			return err
		}
		current, err := readLegacyEntry(ctx, saved.Container.ID, saved.ApplicationID)
		if err != nil || !sameStoppedLegacyEntry(saved, current) {
			return errors.New("control: legacy entry is not the exact stopped backup source")
		}
		return nil
	}
	if err := verifySource(); err != nil {
		return err
	}
	if err := driver.verifyLoadedService(ctx); err != nil {
		return err
	}
	process, err := inspectNativeEntry(ctx, driver.SystemdDriver)
	if err != nil || process.Active || process.PID != 0 || process.ControlPID != 0 {
		return invalid
	}
	runtime := &NativeRuntime{Directory: driver.Directory, Driver: driver}
	state, err := runtime.journal()
	if err == nil {
		// Do not reset an existing revision, rewrite an active installation, or
		// silently recover an interrupted import. Ordinary runtime recovery owns
		// pending state; the handover command remains a one-time initializer.
		if state.Retired || state.Phase != "ready" || state.Current != nil && (state.Current.Revision != desired.Revision || state.Current.ConfigSHA256 != desired.ConfigSHA256 || !bytes.Equal(state.Current.Config, desired.Config)) {
			return errors.New("control: existing native state requires explicit recovery, not reinitialization")
		}
		if err := runtime.verifyConfig(desired); err != nil {
			return err
		}
		if err := verifyNativeEntrySource(driver.Directory, checkpoint, raw, driver.Binding(), desired); err != nil {
			return err
		}
		if state.Current != nil {
			return nil
		}
		// Explicit ordinary recovery may have safely stopped an interrupted
		// first candidate. Its exact retained source/config proof permits retry
		// without creating a second identity or resetting a committed revision.
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := replacePrivate(driver.Directory, "candidate.json", desired.Config); err != nil {
		return err
	}
	if err := driver.Validate(ctx, desired, filepath.Join(driver.Directory, "candidate.json")); err != nil {
		return err
	}
	if err := verifySource(); err != nil {
		return err
	}
	// Persist the source proof before intent. No credentials are placed in this
	// record; the original private checkpoint and its configuration are retained.
	if err := saveNativeEntrySource(driver.Directory, checkpoint, raw, driver.Binding(), desired); err != nil {
		return err
	}
	state = runtimeJournal{Version: 1, Binding: driver.Binding(), Phase: "pending", Candidate: &desired}
	if err := runtime.save(state); err != nil {
		return err
	}
	if err := replacePrivate(driver.Directory, "config.json", desired.Config); err != nil {
		return err
	}
	if err := verifySource(); err != nil {
		return err
	}
	state.Phase, state.Current, state.Candidate = "ready", &desired, nil
	return runtime.save(state)
}

// Private backend addresses/ports may change with the deployment mechanism;
// protocol credentials, inbound identities and TLS/REALITY material may not.
// Compare semantic client sets, not ordering or unrelated generated DNS/API
// configuration. Unknown/duplicate proxy inbounds fail before staging writes.
func retainLegacyEntryIdentities(source, target []byte) error {
	identities := func(raw []byte) (map[string]string, error) {
		var config struct {
			Inbounds []struct {
				Tag      string         `json:"tag"`
				Protocol string         `json:"protocol"`
				Settings map[string]any `json:"settings"`
				Stream   map[string]any `json:"streamSettings"`
			} `json:"inbounds"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&config) != nil {
			return nil, errors.New("control: legacy proxy identities unavailable")
		}
		result := map[string]string{}
		for _, inbound := range config.Inbounds {
			if inbound.Protocol != "vless" && inbound.Protocol != "hysteria" {
				continue
			}
			if inbound.Tag == "" || result[inbound.Tag] != "" || inbound.Settings == nil || inbound.Stream == nil {
				return nil, errors.New("control: ambiguous legacy proxy identity")
			}
			for _, field := range []string{"clients", "users"} {
				if list, ok := inbound.Settings[field].([]any); ok {
					values := make([]string, 0, len(list))
					for _, value := range list {
						encoded, err := json.Marshal(value)
						if err != nil {
							return nil, err
						}
						values = append(values, string(encoded))
					}
					slices.Sort(values)
					inbound.Settings[field] = values
				}
			}
			material, err := json.Marshal([]any{inbound.Protocol, inbound.Settings, inbound.Stream["security"], inbound.Stream["realitySettings"], inbound.Stream["tlsSettings"]})
			if err != nil {
				return nil, err
			}
			result[inbound.Tag] = string(material)
		}
		if len(result) == 0 {
			return nil, errors.New("control: legacy proxy identities missing")
		}
		return result, nil
	}
	before, err := identities(source)
	if err != nil {
		return err
	}
	after, err := identities(target)
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("control: native handover would change proxy credentials or TLS identity")
	}
	return nil
}

type nativeEntrySource struct {
	Version        int    `json:"version"`
	Checkpoint     string `json:"checkpoint"`
	SourceSHA256   string `json:"sourceSha256"`
	Binding        string `json:"binding"`
	ApplicationID  string `json:"applicationId"`
	Revision       uint64 `json:"revision"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

func nativeEntrySourceBytes(checkpoint string, raw []byte, binding string, desired Desired) ([]byte, error) {
	digest := sha256.Sum256(raw)
	id, err := entryPlanIdentity(*desired.Entry)
	if err != nil {
		return nil, err
	}
	return json.Marshal(nativeEntrySource{1, checkpoint, hex.EncodeToString(digest[:]), binding, id, desired.Revision, desired.ConfigSHA256})
}

func verifyNativeEntrySource(directory, checkpoint string, raw []byte, binding string, desired Desired) error {
	expected, err := nativeEntrySourceBytes(checkpoint, raw, binding, desired)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "entry-source.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return errors.New("control: private native entry source proof missing")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(expected, actual) {
		return errors.New("control: native entry source proof changed")
	}
	return nil
}

func saveNativeEntrySource(directory, checkpoint string, raw []byte, binding string, desired Desired) error {
	if _, err := os.Lstat(filepath.Join(directory, "entry-source.json")); err == nil {
		return verifyNativeEntrySource(directory, checkpoint, raw, binding, desired)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := nativeEntrySourceBytes(checkpoint, raw, binding, desired)
	if err != nil {
		return err
	}
	return replacePrivate(directory, "entry-source.json", encoded)
}
