package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type entryInstall struct {
	Version   int            `json:"version"`
	Container EntryContainer `json:"container"`
	Retired   bool           `json:"retired,omitempty"`
}

// ProvisionEntry creates only a Glivela-owned replacement worker. It neither
// claims nor stops a legacy container; the offline handover must first release
// the original listeners. The resource record is durable before activation so
// an interrupted command can resume the same container instead of duplicating
// it. Failed resources remain stopped with their private recovery state.
func ProvisionEntry(ctx context.Context, template EntryContainer, directory, distribution string, desired Desired) (EntryContainer, error) {
	unlock, err := LockDirectory(directory)
	if err != nil {
		return EntryContainer{}, err
	}
	defer unlock()
	return provisionEntryLocked(ctx, template, directory, distribution, desired)
}

func provisionEntryLocked(ctx context.Context, template EntryContainer, directory, distribution string, desired Desired) (EntryContainer, error) {
	invalid := errors.New("control: entry provisioning requires explicit private ownership")
	if os.Geteuid() != 0 || template.ContainerID != "" || template.ImageID != "" || strings.ContainsAny(template.ConfigurationDirectory, ",:\x00\r\n") {
		return EntryContainer{}, invalid
	}
	if template.GID == 0 && template.NetworkAddress == "" {
		return EntryContainer{}, errors.New("control: explicit retained bridge address required for creation")
	}
	var err error
	template, err = resolveEntryEnvironment(ctx, template)
	if err != nil {
		return EntryContainer{}, err
	}
	// Validate the full local scope before invoking Docker; these placeholder
	// IDs never authorize an operation or reach the persisted resource record.
	proposed := template
	proposed.ContainerID = strings.Repeat("0", 64)
	proposed.ImageID = "sha256:" + strings.Repeat("0", 64)
	driver, err := ResolveEntryDriver(proposed, directory, distribution)
	if err != nil || driver.plan(desired) != nil {
		return EntryContainer{}, invalid
	}
	path := filepath.Join(directory, "entry-install.json")
	var saved entryInstall
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128<<10 {
			return EntryContainer{}, invalid
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil || decode(bytes.NewReader(raw), &saved) != nil || saved.Version != 1 || saved.Container.validate() != nil {
			return EntryContainer{}, invalid
		}
		if saved.Retired {
			return EntryContainer{}, errors.New("control: retired entry cannot be provisioned")
		}
		original := saved.Container
		original.ContainerID, original.ImageID = "", ""
		if !reflect.DeepEqual(original, template) {
			return EntryContainer{}, errors.New("control: entry installation scope changed")
		}
		driver.Container = saved.Container
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return EntryContainer{}, statErr
	} else {
		if _, err := (&NativeRuntime{Directory: directory, Driver: driver}).journal(); !errors.Is(err, os.ErrNotExist) {
			return EntryContainer{}, errors.New("control: existing runtime requires explicit resource handover")
		}
		// A new worker may not overwrite a previous mount or arbitrary config.
		if info, err := os.Lstat(filepath.Join(template.ConfigurationDirectory, "config.json")); err == nil {
			owner, ownerErr := entryFileUID(info)
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || ownerErr != nil || owner != template.UID || verifyEntryConfigFile(filepath.Join(template.ConfigurationDirectory, "config.json"), desired.Config) != nil {
				return EntryContainer{}, invalid
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return EntryContainer{}, err
		}
		if err := replacePrivate(directory, "candidate.json", desired.Config); err != nil {
			return EntryContainer{}, err
		}
		if err := validateXrayFile(ctx, driver.binary, driver.binarySHA256, filepath.Join(directory, "candidate.json")); err != nil {
			return EntryContainer{}, err
		}
		if err := driver.writeWorkerConfig(desired.Config); err != nil {
			return EntryContainer{}, err
		}
		image, err := runEntryDocker(ctx, "image", "inspect", "--format", "{{.Id}}", entryImageReference)
		if err != nil {
			return EntryContainer{}, errors.New("control: pinned entry image must be installed before provisioning")
		}
		proposed.ImageID = strings.TrimSpace(string(image))
		if proposed.validate() != nil {
			return EntryContainer{}, invalid
		}
		name := "glivela-entry-" + template.ApplicationID
		// The deterministic name makes a lost create response recoverable. A
		// foreign object with that name fails the complete ownership read-back.
		raw, inspectErr := runEntryDocker(ctx, "container", "inspect", "--format", entryInspectTemplate, name)
		if inspectErr != nil {
			args := []string{"container", "create", "--name", name, "--label", "io.glivela.managed=true", "--label", "io.glivela.entry=" + template.ApplicationID,
				"--read-only", "--restart=no", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--ipc=private", "--workdir=/",
				"--pids-limit=512", "--log-driver=json-file", "--log-opt=max-size=10m", "--log-opt=max-file=3",
				"--mount", "type=bind,src=" + template.ConfigurationDirectory + ",dst=/etc/glivela,readonly,bind-propagation=rprivate",
				"--entrypoint=/usr/local/bin/xray"}
			if template.GID != 0 {
				args = append(args, "--network=host", "--userns=host", "--user=0:"+strconv.FormatUint(uint64(template.GID), 10))
				if len(desired.Entry.HysteriaEndpoints) > 0 {
					args = append(args, "--cap-add=NET_BIND_SERVICE")
				}
			} else {
				args = append(args, "--network="+template.NetworkName, "--user="+strconv.FormatUint(uint64(template.UID), 10), "--sysctl=net.ipv4.ip_unprivileged_port_start=0")
				args = append(args, "--ip="+template.NetworkAddress)
				for _, alias := range template.Aliases {
					args = append(args, "--network-alias="+alias)
				}
				if len(desired.Entry.HysteriaEndpoints) > 0 {
					args = append(args, "--publish=0.0.0.0:443:443/udp")
				}
			}
			// Environment stays in a private file, never in process arguments.
			envPath := filepath.Join(directory, "entry-environment")
			if err := replacePrivate(directory, "entry-environment", []byte(strings.Join(template.Environment, "\n")+"\n")); err != nil {
				return EntryContainer{}, err
			}
			args = append(args, "--env-file="+envPath, entryImageReference, "run", "-format", "json", "-config", "/etc/glivela/config.json")
			_, createErr := runEntryDocker(ctx, args...)
			raw, inspectErr = runEntryDocker(ctx, "container", "inspect", "--format", entryInspectTemplate, name)
			if inspectErr != nil {
				return EntryContainer{}, errors.Join(createErr, inspectErr)
			}
		}
		state, err := decodeEntryContainer(raw)
		if err != nil {
			return EntryContainer{}, err
		}
		proposed.ContainerID = state.ID
		if proposed.verifyState(desired, state) != nil || state.State.Running || state.State.Pid != 0 || state.State.Status != "created" && state.State.Status != "exited" {
			return EntryContainer{}, errors.New("control: created entry ownership or stopped state not confirmed")
		}
		driver.Container = proposed
		saved = entryInstall{Version: 1, Container: proposed}
		record, err := json.Marshal(saved)
		if err != nil {
			return EntryContainer{}, err
		}
		if err := replacePrivate(directory, "entry-install.json", record); err != nil {
			return EntryContainer{}, err
		}
	}
	runtime := &NativeRuntime{Directory: directory, Driver: driver}
	defer func() {
		cleanup, cancel := recoveryContext()
		defer cancel()
		_ = driver.Close(cleanup)
	}()
	if err := runtime.Recover(ctx); err != nil {
		return EntryContainer{}, err
	}
	if err := runtime.Apply(ctx, desired); err != nil {
		return EntryContainer{}, err
	}
	// Stop monitors before releasing the offline lease. The normal node starts
	// them again from the same persisted revision; no stale route is advertised.
	if err := driver.Close(ctx); err != nil {
		return EntryContainer{}, err
	}
	return saved.Container, nil
}
