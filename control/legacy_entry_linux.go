//go:build linux

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"

	glivela "github.com/petauron/glivela"
)

// Private, one-time evidence; never part of the ongoing control protocol.
type legacyEntrySnapshot struct {
	Version       int                 `json:"version"`
	ApplicationID string              `json:"applicationId"`
	Container     entryContainerState `json:"container"`
	Configuration []byte              `json:"configuration"`
}

const legacyEntryLabels = `{"application":{{json (index .Config.Labels "io.vastora.application")}},"id":{{json (index .Config.Labels "io.vastora.application.id")}},"managed":{{json (index .Config.Labels "io.vastora.managed")}},"component":{{json (index .Config.Labels "io.vastora.component")}},"runtime":{{json (index .Config.Labels "io.vastora.proxy-runtime")}}}`

func readLegacyEntry(ctx context.Context, id, application string) (legacyEntrySnapshot, error) {
	invalid := errors.New("control: legacy entry ownership not confirmed")
	if os.Geteuid() != 0 || !exactDockerID(id) || !glivela.ValidIdentifier(application) {
		return legacyEntrySnapshot{}, invalid
	}
	raw, err := runEntryDocker(ctx, "container", "inspect", "--format", legacyEntryLabels, id)
	var labels struct{ Application, ID, Managed, Component, Runtime string }
	if err != nil || json.Unmarshal(raw, &labels) != nil || labels.Application != "vastora-official/meridian" || labels.ID != application || labels.Managed != "true" || labels.Component != "xray" || labels.Runtime != "xray" {
		return legacyEntrySnapshot{}, invalid
	}
	raw, err = runEntryDocker(ctx, "container", "inspect", "--format", entryInspectTemplate, id)
	if err != nil {
		return legacyEntrySnapshot{}, err
	}
	state, err := decodeEntryContainer(raw)
	canonicalizeLegacyEntryMounts(&state)
	if err != nil || state.ID != id || state.Config.Image != entryImageReference || !slices.Equal(state.Config.Entrypoint, []string{"/usr/local/bin/xray"}) || !slices.Equal(state.Config.Cmd, []string{"run", "-c", "/etc/vastora/config.json"}) || state.Host.Privileged || !state.Host.ReadonlyRootfs || state.Host.AutoRemove || state.State.Restarting || state.State.Paused || state.State.Dead || !legacyEntryMountsValid(state) {
		return legacyEntrySnapshot{}, invalid
	}
	switch state.Host.Restart {
	case "no", "always", "unless-stopped":
	default:
		return legacyEntrySnapshot{}, errors.New("control: unsupported legacy entry restart policy")
	}
	mount := state.Mounts[0]
	if mount.Type != "bind" || mount.Destination != "/etc/vastora" || mount.RW || !filepath.IsAbs(mount.Source) || filepath.Clean(mount.Source) != mount.Source {
		return legacyEntrySnapshot{}, invalid
	}
	for parent := mount.Source; parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return legacyEntrySnapshot{}, invalid
		}
	}
	path := filepath.Join(mount.Source, "config.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxMessage {
		return legacyEntrySnapshot{}, invalid
	}
	config, err := os.ReadFile(path)
	if err != nil {
		return legacyEntrySnapshot{}, err
	}
	return legacyEntrySnapshot{Version: 1, ApplicationID: application, Container: state, Configuration: config}, nil
}

// Docker creates these two anonymous volumes from the pinned image's VOLUME
// declarations. Retain them verbatim in the checkpoint and stopped container;
// they are not configuration sources and are never copied or deleted here.
func legacyEntryMountsValid(state entryContainerState) bool {
	if len(state.Mounts) != 1 && len(state.Mounts) != 3 {
		return false
	}
	config := state.Mounts[0]
	if config.Type != "bind" || config.Destination != "/etc/vastora" || config.RW {
		return false
	}
	seen := map[string]bool{}
	for _, mount := range state.Mounts[1:] {
		if mount.Type != "volume" || !mount.RW || mount.Propagation != "" || seen[mount.Destination] || (mount.Destination != "/var/log/xray" && mount.Destination != "/usr/local/etc/xray") {
			return false
		}
		name := filepath.Base(filepath.Dir(mount.Source))
		if !exactDockerID(name) || mount.Source != filepath.Join("/var/lib/docker/volumes", name, "_data") {
			return false
		}
		seen[mount.Destination] = true
	}
	return true
}

// Docker does not promise inspect mount ordering. Preserve every mount field,
// but compare a private, deterministic projection rather than list position.
func canonicalizeLegacyEntryMounts(state *entryContainerState) {
	state.Mounts = slices.Clone(state.Mounts)
	sort.SliceStable(state.Mounts, func(i, j int) bool {
		return state.Mounts[i].Destination < state.Mounts[j].Destination
	})
}

func BackupLegacyEntry(ctx context.Context, directory, container, application string) (string, error) {
	if err := rootEntryCheckpointDirectory(directory); err != nil {
		return "", err
	}
	unlock, err := LockDirectory(directory)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := requireLegacyWriterStopped(ctx); err != nil {
		return "", err
	}
	snapshot, err := readLegacyEntry(ctx, container, application)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	checkpoint, err := os.MkdirTemp(directory, "legacy-entry-")
	if err != nil {
		return "", err
	}
	if err := replacePrivate(checkpoint, "snapshot.json", raw); err != nil {
		return "", err
	}
	current, err := readLegacyEntry(ctx, container, application)
	if err != nil || !reflect.DeepEqual(current, snapshot) {
		return "", errors.New("control: entry changed during backup")
	}
	if err := syncBusinessDirectory(directory); err != nil {
		return "", err
	}
	return filepath.Join(checkpoint, "snapshot.json"), nil
}

// AdoptLegacyEntry permits a short, explicit interruption, not TCP session
// migration. The old container and its exact config remain as private recovery
// resources until independent route acceptance and later explicit retirement.
func AdoptLegacyEntry(ctx context.Context, checkpoint string, template EntryContainer, directory, distribution string, desired Desired) (EntryContainer, error) {
	return adoptLegacyEntry(ctx, checkpoint, template, directory, distribution, desired, false)
}

func adoptLegacyEntry(ctx context.Context, checkpoint string, template EntryContainer, directory, distribution string, desired Desired, nodeLocked bool) (EntryContainer, error) {
	invalid := errors.New("control: entry handover refused")
	if os.Geteuid() != 0 || !filepath.IsAbs(checkpoint) || filepath.Base(checkpoint) != "snapshot.json" || desired.Entry == nil {
		return EntryContainer{}, invalid
	}
	var err error
	template, err = resolveEntryEnvironment(ctx, template)
	if err != nil {
		return EntryContainer{}, err
	}
	if err := rootEntryCheckpointDirectory(filepath.Dir(checkpoint)); err != nil {
		return EntryContainer{}, err
	}
	unlock, err := LockDirectory(filepath.Dir(checkpoint))
	if err != nil {
		return EntryContainer{}, err
	}
	defer unlock()
	info, err := os.Lstat(checkpoint)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2*maxMessage {
		return EntryContainer{}, invalid
	}
	raw, err := os.ReadFile(checkpoint)
	var saved legacyEntrySnapshot
	if err != nil || decode(bytes.NewReader(raw), &saved) != nil || saved.Version != 1 || saved.ApplicationID != template.ApplicationID || !exactDockerID(saved.Container.ID) || len(saved.Container.Mounts) != 1 || !filepath.IsAbs(saved.Container.Mounts[0].Source) {
		return EntryContainer{}, invalid
	}
	if err := requireLegacyWriterStopped(ctx); err != nil {
		return EntryContainer{}, err
	}
	if entryPathsOverlap(directory, filepath.Dir(checkpoint)) || entryPathsOverlap(template.ConfigurationDirectory, saved.Container.Mounts[0].Source) {
		return EntryContainer{}, invalid
	}
	if !nodeLocked {
		nodeUnlock, err := LockDirectory(directory)
		if err != nil {
			return EntryContainer{}, err
		}
		defer nodeUnlock()
	}
	// Retain host/bridge mode and the precise private network identity. The
	// replacement uses its own mount; neither the old config nor IDs are edited.
	if template.GID != 0 {
		if saved.Container.Host.NetworkMode != "host" || saved.Container.Config.User != "0:"+strconv.FormatUint(uint64(template.GID), 10) {
			return EntryContainer{}, invalid
		}
	} else {
		network, ok := saved.Container.Networks[template.NetworkName]
		if !ok || saved.Container.Host.NetworkMode != template.NetworkName || network.NetworkID != template.NetworkID || network.IPAddress == "" || network.IPAddress != template.NetworkAddress || saved.Container.Config.User != strconv.FormatUint(uint64(template.UID), 10) {
			return EntryContainer{}, invalid
		}
		for _, alias := range network.Aliases {
			if !slices.Contains(template.Aliases, alias) {
				return EntryContainer{}, errors.New("control: entry handover would lose an ingress network alias")
			}
		}
	}
	if !slices.Equal(saved.Container.Config.Env, template.Environment) {
		return EntryContainer{}, errors.New("control: entry handover would change its environment")
	}
	current, err := readLegacyEntry(ctx, saved.Container.ID, saved.ApplicationID)
	if err != nil {
		return EntryContainer{}, err
	}
	phasePath := filepath.Join(filepath.Dir(checkpoint), "switch.json")
	if phase, err := os.ReadFile(phasePath); err == nil {
		if string(phase) == "awaiting-routes" && sameStoppedLegacyEntry(saved, current) {
			return provisionEntryLocked(ctx, template, directory, distribution, desired)
		}
		if string(phase) == "pending" {
			recovery, cancel := recoveryContext()
			defer cancel()
			if err := recoverLegacyEntry(recovery, checkpoint, saved, template, directory, distribution, desired); err != nil {
				return EntryContainer{}, err
			}
			return EntryContainer{}, errors.New("control: interrupted entry handover restored source; inspect before retry")
		}
		return EntryContainer{}, errors.New("control: interrupted entry handover requires recovery before retry")
	} else if !errors.Is(err, os.ErrNotExist) {
		return EntryContainer{}, err
	}
	if !reflect.DeepEqual(current, saved) {
		return EntryContainer{}, errors.New("control: entry source changed after backup")
	}
	// Preflight candidate syntax before stopping the old worker.
	proposed := template
	proposed.ContainerID, proposed.ImageID = saved.Container.ID, saved.Container.Image
	driver, err := ResolveEntryDriver(proposed, directory, distribution)
	if err != nil || driver.plan(desired) != nil {
		return EntryContainer{}, invalid
	}
	if err := replacePrivate(directory, "candidate.json", desired.Config); err != nil {
		return EntryContainer{}, err
	}
	if err := validateXrayFile(ctx, driver.binary, driver.binarySHA256, filepath.Join(directory, "candidate.json")); err != nil {
		return EntryContainer{}, err
	}
	if _, err := runEntryDocker(ctx, "image", "inspect", entryImageReference); err != nil {
		return EntryContainer{}, errors.New("control: pinned entry image unavailable before cutover")
	}
	if err := replacePrivate(filepath.Dir(checkpoint), "switch.json", []byte("pending")); err != nil {
		return EntryContainer{}, err
	}
	if _, err := runEntryDocker(ctx, "container", "update", "--restart=no", saved.Container.ID); err != nil {
		return EntryContainer{}, err
	}
	if saved.Container.State.Running || saved.Container.State.Pid != 0 {
		if _, err := runEntryDocker(ctx, "container", "stop", "--time=3", saved.Container.ID); err != nil {
			return EntryContainer{}, err
		}
	}
	stopped, err := readLegacyEntry(ctx, saved.Container.ID, saved.ApplicationID)
	if err != nil || !sameStoppedLegacyEntry(saved, stopped) {
		return EntryContainer{}, errors.New("control: old entry stop was not confirmed")
	}
	container, err := provisionEntryLocked(ctx, template, directory, distribution, desired)
	if err != nil {
		// Keep the failed replacement stopped before restoring a previously
		// running source; never put two writers/listeners back into service.
		recovery, cancel := recoveryContext()
		defer cancel()
		if recoveryErr := recoverLegacyEntry(recovery, checkpoint, saved, template, directory, distribution, desired); recoveryErr != nil {
			return EntryContainer{}, errors.Join(err, recoveryErr)
		}
		return EntryContainer{}, err
	}
	if err := replacePrivate(filepath.Dir(checkpoint), "switch.json", []byte("awaiting-routes")); err != nil {
		return EntryContainer{}, err
	}
	return container, nil
}

func recoverLegacyEntry(ctx context.Context, checkpoint string, saved legacyEntrySnapshot, template EntryContainer, directory, distribution string, desired Desired) error {
	raw, err := os.ReadFile(filepath.Join(directory, "entry-install.json"))
	if err == nil {
		var record entryInstall
		if decode(bytes.NewReader(raw), &record) != nil || record.Version != 1 || record.Container.ApplicationID != saved.ApplicationID {
			return errors.New("control: replacement ownership cannot be recovered")
		}
		driver, err := ResolveEntryDriver(record.Container, directory, distribution)
		if err != nil {
			return err
		}
		if err := driver.Stop(ctx, desired); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	current, err := readLegacyEntry(ctx, saved.Container.ID, saved.ApplicationID)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(current, saved) {
		return replacePrivate(filepath.Dir(checkpoint), "switch.json", []byte("rolled-back"))
	}
	normalized := current
	normalized.Container.Host.Restart = saved.Container.Host.Restart
	if !sameStoppedLegacyEntry(saved, current) && !reflect.DeepEqual(normalized, saved) {
		return errors.New("control: source ownership changed during entry recovery")
	}
	switch saved.Container.Host.Restart {
	case "no", "always", "unless-stopped":
	default:
		return errors.New("control: unsupported source restart policy")
	}
	if _, err := runEntryDocker(ctx, "container", "update", "--restart="+saved.Container.Host.Restart, saved.Container.ID); err != nil {
		return err
	}
	if saved.Container.State.Running && !current.Container.State.Running {
		if _, err := runEntryDocker(ctx, "container", "start", saved.Container.ID); err != nil {
			return err
		}
	}
	actual, err := readLegacyEntry(ctx, saved.Container.ID, saved.ApplicationID)
	if err != nil || actual.Container.State.Running != saved.Container.State.Running || actual.Container.Host.Restart != saved.Container.Host.Restart || !bytes.Equal(actual.Configuration, saved.Configuration) {
		return errors.New("control: restored entry state not confirmed")
	}
	return replacePrivate(filepath.Dir(checkpoint), "switch.json", []byte("rolled-back"))
}

func sameStoppedLegacyEntry(saved, current legacyEntrySnapshot) bool {
	canonicalizeLegacyEntryMounts(&saved.Container)
	canonicalizeLegacyEntryMounts(&current.Container)
	if current.Container.State.Running || current.Container.State.Restarting || current.Container.State.Pid != 0 || current.Container.Host.Restart != "no" {
		return false
	}
	current.Container.State = saved.Container.State
	current.Container.Host.Restart = saved.Container.Host.Restart
	current.Container.Networks = maps.Clone(current.Container.Networks)
	// Docker releases the live address while stopped. Retain and compare the
	// immutable endpoint/IPAM declarations; normalize only the live field.
	for name, network := range current.Container.Networks {
		original, found := saved.Container.Networks[name]
		if !found || network.IPAddress != "" && network.IPAddress != original.IPAddress {
			return false
		}
		network.IPAddress = original.IPAddress
		current.Container.Networks[name] = network
	}
	return reflect.DeepEqual(saved, current)
}

func rootEntryCheckpointDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return errors.New("control: private root-owned checkpoint directory required")
	}
	for parent := directory; parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return errors.New("control: unsafe entry checkpoint ancestry")
		}
		uid, err := entryFileUID(info)
		if err != nil || uid != 0 || parent == directory && info.Mode().Perm()&0077 != 0 {
			return errors.New("control: entry checkpoint owner or permissions differ")
		}
	}
	return nil
}
