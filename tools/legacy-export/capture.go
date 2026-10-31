package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// This is one-time inspection of the previous Center, not a Docker runtime
// adapter or a dependency of the Glivela controller/node. The command never
// stops, updates or reconfigures any container.
type oldCenterContainer struct {
	ID         string            `json:"id"`
	Labels     map[string]string `json:"labels"`
	Entrypoint []string          `json:"entrypoint"`
	Command    []string          `json:"command"`
	Restart    string            `json:"restart"`
	State      struct {
		Status     string
		Running    bool
		Restarting bool
		Pid        int
		StartedAt  string
		FinishedAt string
	} `json:"state"`
	Mounts []struct {
		Source, Destination string
		RW                  bool
	} `json:"mounts"`
}

type finalCapture struct {
	Version        int    `json:"version"`
	ContainerID    string `json:"containerId"`
	DatabaseSHA256 string `json:"databaseSha256"`
	StartedAt      string `json:"startedAt"`
	StoppedAt      string `json:"stoppedAt"`
	CapturedAt     string `json:"capturedAt"`
}

func captureFinalCommand(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("capture-final", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	data := flags.String("data-directory", "", "old Center host data directory")
	backup := flags.String("backup-directory", "", "new private offline backup directory")
	id := flags.String("container", "", "full stopped old Center container ID")
	if flags.Parse(args) != nil || flags.NArg() != 0 || os.Geteuid() != 0 {
		return errors.New("root final capture arguments required")
	}
	return captureFinal(ctx, *data, *backup, *id, inspectOldContainers)
}

func validContainerID(id string) bool {
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == 32 && strings.ToLower(id) == id
}

func pathsOverlap(a, b string) bool {
	inside := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	return inside(a, b) || inside(b, a)
}

func stoppedCenter(containers []oldCenterContainer, id, directory string) (oldCenterContainer, error) {
	invalid := errors.New("final capture requires the stopped, non-restarting old Center and exclusive data ownership")
	if !validContainerID(id) || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || len(containers) == 0 || len(containers) > 256 {
		return oldCenterContainer{}, invalid
	}
	var found *oldCenterContainer
	seen := map[string]bool{}
	for i := range containers {
		c := &containers[i]
		if !validContainerID(c.ID) || seen[c.ID] {
			return oldCenterContainer{}, invalid
		}
		seen[c.ID] = true
		owns := false
		for _, mount := range c.Mounts {
			if !mount.RW || mount.Source == "" {
				continue
			}
			if !filepath.IsAbs(mount.Source) || filepath.Clean(mount.Source) != mount.Source {
				return oldCenterContainer{}, invalid
			}
			if !pathsOverlap(mount.Source, directory) {
				continue
			}
			if c.ID != id {
				if c.Restart != "no" || c.State.Running || c.State.Restarting || c.State.Pid != 0 || c.State.Status != "exited" && c.State.Status != "created" {
					return oldCenterContainer{}, invalid
				}
				continue
			}
			if mount.Source != directory || mount.Destination != "/var/lib/vastora" {
				return oldCenterContainer{}, invalid
			}
			if owns {
				return oldCenterContainer{}, invalid
			}
			owns = true
		}
		if c.ID != id {
			continue
		}
		if !owns || c.Labels["io.vastora.managed"] != "true" || c.Labels["io.vastora.component"] != "center" || !reflect.DeepEqual(c.Entrypoint, []string{"/usr/local/bin/vastora"}) || len(c.Command) < 4 || c.Command[0] != "center" || c.Command[1] != "serve" || c.Restart != "no" || c.State.Status != "exited" || c.State.Running || c.State.Restarting || c.State.Pid != 0 {
			return oldCenterContainer{}, invalid
		}
		dataFlags := 0
		for j, arg := range c.Command {
			if arg == "--data-dir" {
				if j+1 >= len(c.Command) || c.Command[j+1] != "/var/lib/vastora" {
					return oldCenterContainer{}, invalid
				}
				dataFlags++
			}
			if strings.HasPrefix(arg, "--data-dir=") {
				return oldCenterContainer{}, invalid
			}
		}
		start, err := time.Parse(time.RFC3339Nano, c.State.StartedAt)
		stop, stopErr := time.Parse(time.RFC3339Nano, c.State.FinishedAt)
		if dataFlags != 1 || err != nil || stopErr != nil || start.IsZero() || stop.Before(start) {
			return oldCenterContainer{}, invalid
		}
		found = c
	}
	if found == nil {
		return oldCenterContainer{}, invalid
	}
	return *found, nil
}

func captureFinal(ctx context.Context, data, backup, id string, inspect func(context.Context) ([]oldCenterContainer, error)) error {
	if !filepath.IsAbs(backup) || filepath.Clean(backup) != backup || pathsOverlap(data, backup) {
		return errors.New("independent new backup directory required")
	}
	if err := safeParent(filepath.Join(data, "center.db")); err != nil {
		return err
	}
	if err := safeParent(backup); err != nil {
		return err
	}
	containers, err := inspect(ctx)
	if err != nil {
		return err
	}
	before, err := stoppedCenter(containers, id, data)
	if err != nil {
		return err
	}
	dbPath, keyPath := filepath.Join(data, "center.db"), filepath.Join(data, "center.key")
	if err := standalone(dbPath); err != nil {
		return err
	}
	database, err := privateFile(dbPath, maxDatabaseSnapshotBytes)
	if err != nil || len(database) == 0 {
		return errors.New("nonempty original Center database required")
	}
	defer clear(database)
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := privateFile(keyPath, 32)
	if err != nil || len(key) != 32 {
		return errors.New("original Center key required")
	}
	defer clear(key)
	if err := os.Mkdir(backup, 0700); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(backup))
	if err != nil {
		return err
	}
	err = parent.Sync()
	parent.Close()
	if err != nil {
		return err
	}
	if err := writeNewPrivate(filepath.Join(backup, "center.db"), database); err != nil {
		return err
	}
	if err := writeNewPrivate(filepath.Join(backup, "center.key"), key); err != nil {
		return err
	}
	containers, err = inspect(ctx)
	if err != nil {
		return err
	}
	after, err := stoppedCenter(containers, id, data)
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("old writer state changed during final capture")
	}
	// Recheck both live bytes and Docker state. A failed/changed capture keeps
	// private partial files, but receives no completion marker or authority.
	if err := standalone(dbPath); err != nil {
		return err
	}
	again, err := privateFile(dbPath, maxDatabaseSnapshotBytes)
	defer clear(again)
	if err != nil || !bytes.Equal(database, again) {
		return errors.New("old database changed during final capture")
	}
	keyAgain, err := privateFile(keyPath, 32)
	defer clear(keyAgain)
	if err != nil || !bytes.Equal(key, keyAgain) {
		return errors.New("old key changed during final capture")
	}
	digest := sha256.Sum256(database)
	raw, err := json.Marshal(finalCapture{Version: 1, ContainerID: id, DatabaseSHA256: hex.EncodeToString(digest[:]), StartedAt: before.State.StartedAt, StoppedAt: before.State.FinishedAt, CapturedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	return writeNewPrivate(filepath.Join(backup, "capture.json"), raw)
}

type inspectOutput struct{ bytes.Buffer }

func (b *inspectOutput) Write(p []byte) (int, error) {
	if len(p) > (4<<20)-b.Len() {
		return 0, errors.New("container inventory too large")
	}
	return b.Buffer.Write(p)
}

func inspectOldContainers(ctx context.Context) ([]oldCenterContainer, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var ids inspectOutput
	list := exec.CommandContext(ctx, "/usr/bin/docker", "--host=unix:///var/run/docker.sock", "container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}")
	list.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	list.Stdout = &ids
	if list.Run() != nil {
		return nil, errors.New("old container inventory unavailable")
	}
	arguments := strings.Fields(ids.String())
	if len(arguments) == 0 || len(arguments) > 256 {
		return nil, errors.New("invalid old container inventory")
	}
	for _, id := range arguments {
		if !validContainerID(id) {
			return nil, errors.New("invalid old container identity")
		}
	}
	const template = `{"id":{{json .Id}},"labels":{"io.vastora.managed":{{json (index .Config.Labels "io.vastora.managed")}},"io.vastora.component":{{json (index .Config.Labels "io.vastora.component")}}},"entrypoint":{{json .Config.Entrypoint}},"command":{{json .Config.Cmd}},"restart":{{json .HostConfig.RestartPolicy.Name}},"state":{{json .State}},"mounts":{{json .Mounts}}}`
	command := exec.CommandContext(ctx, "/usr/bin/docker", append([]string{"--host=unix:///var/run/docker.sock", "container", "inspect", "--format", template}, arguments...)...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	var output inspectOutput
	command.Stdout = &output
	if command.Run() != nil {
		return nil, errors.New("old container inspection unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	var containers []oldCenterContainer
	for range arguments {
		var c oldCenterContainer
		if decoder.Decode(&c) != nil {
			return nil, errors.New("invalid old container inspection")
		}
		for i := range c.Mounts {
			if c.Mounts[i].RW && filepath.IsAbs(c.Mounts[i].Source) {
				if canonical, err := filepath.EvalSymlinks(c.Mounts[i].Source); err == nil {
					c.Mounts[i].Source = canonical
				}
			}
		}
		containers = append(containers, c)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("unexpected old container inspection")
	}
	return containers, nil
}
