package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
)

const entryImageReference = "ghcr.io/xtls/xray-core:26.7.28@sha256:b697cda1588faca696ab7f7755dd1161f60862af3ff6026300e44cff6aedd558"

// EntryContainer is a local ownership record, not a field of the remote node
// protocol. Importing a legacy container requires separate offline handover;
// neither a matching container name nor an application ID grants ownership.
// This record does not itself install, adopt, stop or restart anything.
type EntryContainer struct {
	ApplicationID          string `json:"applicationId"`
	ContainerID            string `json:"containerId"`
	ImageID                string `json:"imageId"`
	ConfigurationDirectory string `json:"configurationDirectory"`
	// Host sockets retain the dedicated immutable GID. A retained bridge has
	// GID zero and instead binds the exact network ID, interface and worker UID.
	GID            uint32   `json:"gid"`
	UID            uint32   `json:"uid"`
	NetworkID      string   `json:"networkId,omitempty"`
	NetworkName    string   `json:"networkName,omitempty"`
	Bridge         string   `json:"bridge,omitempty"`
	NetworkAddress string   `json:"networkAddress,omitempty"`
	Aliases        []string `json:"aliases,omitempty"`
	Environment    []string `json:"environment"`
}

type entryContainerNetwork struct {
	NetworkID  string
	Aliases    []string
	IPAddress  string
	IPAMConfig *struct{ IPv4Address string }
}

type entryContainerState struct {
	ID, Image string
	Config    struct {
		Image, User, WorkingDir string
		Labels                  map[string]string
		Entrypoint, Cmd, Env    []string
	}
	Host struct {
		NetworkMode, UsernsMode, PidMode, IpcMode string
		Privileged, ReadonlyRootfs, AutoRemove    bool
		Restart                                   string
		CapAdd, CapDrop, SecurityOpt, GroupAdd    []string
		PortBindings, Sysctls, Tmpfs              map[string]json.RawMessage
		Devices                                   []json.RawMessage
		DeviceRequests                            []json.RawMessage
	}
	State struct {
		Status, StartedAt                 string
		Running, Restarting, Paused, Dead bool
		Pid                               int
	}
	Mounts []struct {
		Type, Source, Destination, Propagation string
		RW                                     bool
	}
	Networks map[string]entryContainerNetwork
}

// Keep the projection explicit: never request all inspect data, labels, logs,
// process arguments beyond this known service, or an environment dump on stdout.
// Env is compared in memory only and is never included in diagnostics/receipts.
const entryInspectTemplate = `{"ID":{{json .Id}},"Image":{{json .Image}},"Config":{"Image":{{json .Config.Image}},"User":{{json .Config.User}},"WorkingDir":{{json .Config.WorkingDir}},"Labels":{"io.glivela.managed":{{json (index .Config.Labels "io.glivela.managed")}},"io.glivela.entry":{{json (index .Config.Labels "io.glivela.entry")}}},"Entrypoint":{{json .Config.Entrypoint}},"Cmd":{{json .Config.Cmd}},"Env":{{json .Config.Env}}},"Host":{"NetworkMode":{{json .HostConfig.NetworkMode}},"UsernsMode":{{json .HostConfig.UsernsMode}},"PidMode":{{json .HostConfig.PidMode}},"IpcMode":{{json .HostConfig.IpcMode}},"Privileged":{{json .HostConfig.Privileged}},"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"AutoRemove":{{json .HostConfig.AutoRemove}},"Restart":{{json .HostConfig.RestartPolicy.Name}},"CapAdd":{{json .HostConfig.CapAdd}},"CapDrop":{{json .HostConfig.CapDrop}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},"GroupAdd":{{json .HostConfig.GroupAdd}},"PortBindings":{{json .HostConfig.PortBindings}},"Sysctls":{{json .HostConfig.Sysctls}},"Tmpfs":{{json .HostConfig.Tmpfs}},"Devices":{{json .HostConfig.Devices}},"DeviceRequests":{{json .HostConfig.DeviceRequests}}},"State":{"Status":{{json .State.Status}},"Running":{{json .State.Running}},"Restarting":{{json .State.Restarting}},"Paused":{{json .State.Paused}},"Dead":{{json .State.Dead}},"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}}},"Mounts":{{json .Mounts}},"Networks":{{json .NetworkSettings.Networks}}}`

func exactDockerID(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && value == strings.ToLower(value)
}

func (c EntryContainer) validate() error {
	if !glivela.ValidIdentifier(c.ApplicationID) || !exactDockerID(c.ContainerID) || !strings.HasPrefix(c.ImageID, "sha256:") || !exactDockerID(strings.TrimPrefix(c.ImageID, "sha256:")) ||
		!filepath.IsAbs(c.ConfigurationDirectory) || filepath.Clean(c.ConfigurationDirectory) != c.ConfigurationDirectory || c.ConfigurationDirectory == "/" || len(c.Environment) > 64 {
		return errors.New("control: invalid entry container ownership record")
	}
	if c.GID != 0 {
		if c.UID != 0 || c.GID == 65534 || c.GID == uint32(os.Getegid()) || c.NetworkID != "" || c.NetworkName != "" || c.Bridge != "" || c.NetworkAddress != "" {
			return errors.New("control: dedicated entry host identity required")
		}
	} else if c.UID == 0 || c.UID == 65534 || !exactDockerID(c.NetworkID) || !glivela.ValidIdentifier(c.NetworkName) || !validBridgeName(c.Bridge) {
		return errors.New("control: exact retained entry bridge identity required")
	}
	if c.NetworkAddress != "" {
		address, err := netip.ParseAddr(c.NetworkAddress)
		if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != c.NetworkAddress {
			return errors.New("control: invalid retained entry bridge address")
		}
	}
	for _, value := range c.Environment {
		key, _, found := strings.Cut(value, "=")
		if !found || key == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("control: invalid installed entry environment")
		}
	}
	if len(c.Aliases) > 16 || c.GID != 0 && len(c.Aliases) != 0 {
		return errors.New("control: invalid entry network aliases")
	}
	for i, alias := range c.Aliases {
		if !glivela.ValidIdentifier(alias) || slices.Contains(c.Aliases[:i], alias) {
			return errors.New("control: invalid entry network alias")
		}
	}
	return nil
}

func validBridgeName(value string) bool {
	if len(value) == 0 || len(value) > 15 || value[0] == '-' {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// Fingerprint binds this versioned execution snapshot without exposing its
// environment or paths. It is deliberately NOT Driver.Binding: ordinary owned
// image updates may replace a container, while the application's stable local
// runtime identity and recovery journal remain unchanged.
func (c EntryContainer) Fingerprint() string {
	if c.validate() != nil {
		return ""
	}
	raw, _ := json.Marshal(c)
	h := sha256.Sum256(raw)
	return "glivela-entry-container-v1:" + hex.EncodeToString(h[:])
}

func (c EntryContainer) verifyState(d Desired, state entryContainerState) error {
	invalid := errors.New("control: entry container differs from owned installation")
	if c.validate() != nil || d.Entry == nil || d.Landing != nil || d.Validate() != nil {
		return invalid
	}
	id, err := entryPlanIdentity(*d.Entry)
	if err != nil || id != c.ApplicationID || state.ID != c.ContainerID || state.Image != c.ImageID || state.Config.Image != entryImageReference ||
		state.Config.Labels["io.glivela.managed"] != "true" || state.Config.Labels["io.glivela.entry"] != id ||
		!slices.Equal(state.Config.Entrypoint, []string{"/usr/local/bin/xray"}) || !slices.Equal(state.Config.Cmd, []string{"run", "-format", "json", "-config", "/etc/glivela/config.json"}) ||
		state.Config.WorkingDir != "/" || !slices.Equal(state.Config.Env, c.Environment) {
		return invalid
	}
	h := state.Host
	if h.Privileged || !h.ReadonlyRootfs || h.AutoRemove || h.Restart != "no" || h.PidMode != "" || h.IpcMode != "private" ||
		len(h.Tmpfs) != 0 || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.GroupAdd) != 0 ||
		!slices.Equal(h.CapDrop, []string{"ALL"}) || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true"}) {
		return invalid
	}
	hy2 := len(d.Entry.HysteriaEndpoints) > 0
	if c.GID != 0 && hy2 {
		if !slices.Equal(h.CapAdd, []string{"CAP_NET_BIND_SERVICE"}) {
			return invalid
		}
	} else if len(h.CapAdd) != 0 {
		return invalid
	}
	if len(state.Mounts) != 1 {
		return invalid
	}
	m := state.Mounts[0]
	if m.Type != "bind" || m.Source != c.ConfigurationDirectory || m.Destination != "/etc/glivela" || m.RW || m.Propagation != "rprivate" {
		return invalid
	}
	if len(state.Networks) != 1 {
		return invalid
	}
	if c.GID != 0 {
		if state.Config.User != "0:"+strconv.FormatUint(uint64(c.GID), 10) || h.NetworkMode != "host" || h.UsernsMode != "host" || len(h.PortBindings) != 0 || len(h.Sysctls) != 0 {
			return invalid
		}
		if _, ok := state.Networks["host"]; !ok {
			return invalid
		}
	} else {
		if state.Config.User != strconv.FormatUint(uint64(c.UID), 10) || h.NetworkMode != c.NetworkName || h.UsernsMode != "" || state.Networks[c.NetworkName].NetworkID != c.NetworkID {
			return invalid
		}
		for _, alias := range c.Aliases {
			if !slices.Contains(state.Networks[c.NetworkName].Aliases, alias) {
				return invalid
			}
		}
		if c.NetworkAddress != "" {
			network := state.Networks[c.NetworkName]
			if network.IPAMConfig == nil || network.IPAMConfig.IPv4Address != c.NetworkAddress || state.State.Running && network.IPAddress != c.NetworkAddress {
				return invalid
			}
		}
		// Retained non-root bridge workers already use this namespaced setting.
		// Do not alter a host sysctl or add bind capabilities to make HY2 work.
		var firstPort string
		if len(h.Sysctls) != 1 || json.Unmarshal(h.Sysctls["net.ipv4.ip_unprivileged_port_start"], &firstPort) != nil || firstPort != "0" {
			return invalid
		}
		if hy2 {
			var bindings []struct{ HostIP, HostPort string }
			if len(h.PortBindings) != 1 || json.Unmarshal(h.PortBindings["443/udp"], &bindings) != nil || len(bindings) != 1 || bindings[0].HostIP != "0.0.0.0" || bindings[0].HostPort != "443" {
				return invalid
			}
		} else if len(h.PortBindings) != 0 {
			return invalid
		}
	}
	return nil
}

type entryDockerOutput struct{ bytes.Buffer }

func (o *entryDockerOutput) Write(p []byte) (int, error) {
	if len(p) > (1<<20)-o.Len() {
		return 0, errors.New("control: Docker inspection exceeds limit")
	}
	return o.Buffer.Write(p)
}

// Only the local system Docker daemon is used. Inherited DOCKER_HOST,
// DOCKER_CONTEXT, plugin paths and environment proxy settings cannot redirect
// privileged inspection to another daemon. No stderr or inspect output leaks.
func runEntryDocker(ctx context.Context, arguments ...string) ([]byte, error) {
	timeout := 5 * time.Second
	if len(arguments) == 3 && arguments[0] == "image" && arguments[1] == "pull" && arguments[2] == entryImageReference {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/docker", append([]string{"--host=unix:///var/run/docker.sock"}, arguments...)...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "DOCKER_CONFIG=/var/empty/glivela-docker"}
	command.WaitDelay = time.Second
	var output entryDockerOutput
	command.Stdout = &output
	if command.Run() != nil {
		return nil, errors.New("control: entry Docker operation unavailable")
	}
	return output.Bytes(), nil
}

// An omitted local environment means the immutable image's own defaults, not
// the node process environment. Explicit retained environments are unchanged.
func resolveEntryEnvironment(ctx context.Context, template EntryContainer) (EntryContainer, error) {
	if template.Environment != nil {
		return template, nil
	}
	raw, err := runEntryDocker(ctx, "image", "inspect", "--format", "{{json .Config.Env}}", entryImageReference)
	if err != nil {
		if _, err := runEntryDocker(ctx, "image", "pull", entryImageReference); err != nil {
			return EntryContainer{}, errors.New("control: pinned entry image unavailable")
		}
		raw, err = runEntryDocker(ctx, "image", "inspect", "--format", "{{json .Config.Env}}", entryImageReference)
	}
	if err != nil || json.Unmarshal(raw, &template.Environment) != nil {
		return EntryContainer{}, errors.New("control: pinned entry environment unavailable")
	}
	return template, nil
}

func decodeEntryContainer(raw []byte) (entryContainerState, error) {
	var state entryContainerState
	if len(raw) > 1<<20 || len(raw) == 0 {
		return state, errors.New("control: invalid entry inspection")
	}
	// The projection includes evolving Docker mount/network metadata. Only the
	// explicit security/ownership fields above are consumed, never arbitrary data.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var extra any
	if decoder.Decode(&state) != nil || decoder.Decode(&extra) != io.EOF {
		return entryContainerState{}, errors.New("control: invalid entry inspection")
	}
	return state, nil
}

// Verify is read-only and requires actual running state. It is not a route
// health result: the caller must also verify config bytes, listeners and gates.
func (c EntryContainer) Verify(ctx context.Context, d Desired) error {
	if c.validate() != nil || d.Entry == nil || d.Validate() != nil {
		return errors.New("control: valid owned entry required")
	}
	raw, err := runEntryDocker(ctx, "container", "inspect", "--format", entryInspectTemplate, c.ContainerID)
	if err != nil {
		return err
	}
	state, err := decodeEntryContainer(raw)
	if err != nil {
		return err
	}
	if err := c.verifyState(d, state); err != nil {
		return err
	}
	if !state.State.Running || state.State.Restarting || state.State.Paused || state.State.Dead || state.State.Pid <= 0 || state.State.Status != "running" {
		return errors.New("control: owned entry container is not running")
	}
	if c.GID == 0 {
		return c.verifyBridge(ctx)
	}
	return nil
}

const entryBridgeTemplate = `{"Id":{{json .Id}},"Name":{{json .Name}},"Driver":{{json .Driver}},"Scope":{{json .Scope}},"Internal":{{json .Internal}},"Ingress":{{json .Ingress}},"Options":{{json .Options}}}`

func (c EntryContainer) verifyBridge(ctx context.Context) error {
	raw, err := runEntryDocker(ctx, "network", "inspect", "--format", entryBridgeTemplate, c.NetworkID)
	if err != nil {
		return err
	}
	return c.verifyBridgeState(raw)
}

func (c EntryContainer) verifyBridgeState(raw []byte) error {
	var state struct {
		ID, Name, Driver, Scope string
		Internal, Ingress       bool
		Options                 map[string]string
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if len(raw) > 1<<20 || decoder.Decode(&state) != nil || decoder.Decode(&extra) != io.EOF || state.ID != c.NetworkID || state.Name != c.NetworkName || state.Driver != "bridge" || state.Scope != "local" || state.Internal || state.Ingress {
		return errors.New("control: entry bridge network identity changed")
	}
	bridge := state.Options["com.docker.network.bridge.name"]
	if bridge == "" && exactDockerID(state.ID) {
		bridge = "br-" + state.ID[:12]
	}
	if bridge != c.Bridge {
		return errors.New("control: entry bridge interface changed")
	}
	return nil
}
