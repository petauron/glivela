package control

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	glivela "github.com/petauron/glivela"
)

func entryContainerFixture(t *testing.T, host bool) (EntryContainer, Desired, entryContainerState) {
	t.Helper()
	d := entryArtifact(t, "entry-container-example", 1)
	c := EntryContainer{ApplicationID: "entry-container-example", ContainerID: strings.Repeat("a", 64), ImageID: "sha256:" + strings.Repeat("b", 64), ConfigurationDirectory: t.TempDir(), Environment: []string{"PATH=/usr/bin:/bin"}}
	var state entryContainerState
	state.ID, state.Image = c.ContainerID, c.ImageID
	state.Config.Image = entryImageReference
	state.Config.WorkingDir = "/"
	state.Config.Labels = map[string]string{"io.glivela.managed": "true", "io.glivela.entry": c.ApplicationID}
	state.Config.Entrypoint = []string{"/usr/local/bin/xray"}
	state.Config.Cmd = []string{"run", "-format", "json", "-config", "/etc/glivela/config.json"}
	state.Config.Env = append([]string{}, c.Environment...)
	state.Host.ReadonlyRootfs = true
	state.Host.Restart = "no"
	state.Host.IpcMode = "private"
	state.Host.CapDrop = []string{"ALL"}
	state.Host.SecurityOpt = []string{"no-new-privileges:true"}
	state.State.Status, state.State.Running, state.State.Pid = "running", true, 12345
	state.Mounts = append(state.Mounts, struct {
		Type, Source, Destination, Propagation string
		RW                                     bool
	}{"bind", c.ConfigurationDirectory, "/etc/glivela", "rprivate", false})
	if host {
		c.GID = 12346
		state.Config.User = "0:12346"
		state.Host.NetworkMode, state.Host.UsernsMode = "host", "host"
		state.Networks = map[string]struct{ NetworkID string }{"host": {}}
	} else {
		c.UID, c.NetworkID, c.NetworkName, c.Bridge = 65532, strings.Repeat("c", 64), "glivela-entry-example", "br-fixture"
		state.Config.User = "65532"
		state.Host.NetworkMode = c.NetworkName
		state.Host.Sysctls = map[string]json.RawMessage{"net.ipv4.ip_unprivileged_port_start": json.RawMessage(`"0"`)}
		state.Networks = map[string]struct{ NetworkID string }{c.NetworkName: {NetworkID: c.NetworkID}}
	}
	return c, d, state
}

func TestEntryContainerReadbackRejectsOwnershipAndSecurityDrift(t *testing.T) {
	for _, host := range []bool{false, true} {
		for _, fault := range []string{"none", "id", "image-id", "floating-image", "label", "old-owner", "entrypoint", "command", "environment", "workdir", "privileged", "writable-root", "autoremove", "restart", "pid", "ipc", "cap", "missing-cap-drop", "security-opt", "group", "ports", "sysctl", "tmpfs", "device", "gpu", "mount-source", "mount-rw", "mount-shadow", "propagation", "user", "network-mode", "userns", "extra-network", "network-id"} {
			t.Run(strings.Join([]string{map[bool]string{true: "host", false: "bridge"}[host], fault}, "/"), func(t *testing.T) {
				c, d, state := entryContainerFixture(t, host)
				switch fault {
				case "id":
					state.ID = strings.Repeat("d", 64)
				case "image-id":
					state.Image = "sha256:" + strings.Repeat("d", 64)
				case "floating-image":
					state.Config.Image = "ghcr.io/xtls/xray-core:latest"
				case "label":
					state.Config.Labels["io.glivela.entry"] = "other-entry"
				case "old-owner":
					delete(state.Config.Labels, "io.glivela.managed")
					state.Config.Labels["io.vastora.managed"] = "true"
				case "entrypoint":
					state.Config.Entrypoint = []string{"/bin/sh"}
				case "command":
					state.Config.Cmd = append(state.Config.Cmd, "-config", "/tmp/unowned")
				case "environment":
					state.Config.Env = append(state.Config.Env, "XRAY_LOCATION_CONFIG=/tmp/unowned")
				case "workdir":
					state.Config.WorkingDir = "/tmp"
				case "privileged":
					state.Host.Privileged = true
				case "writable-root":
					state.Host.ReadonlyRootfs = false
				case "autoremove":
					state.Host.AutoRemove = true
				case "restart":
					state.Host.Restart = "unless-stopped"
				case "pid":
					state.Host.PidMode = "host"
				case "ipc":
					state.Host.IpcMode = "host"
				case "cap":
					state.Host.CapAdd = []string{"CAP_SYS_ADMIN"}
				case "missing-cap-drop":
					state.Host.CapDrop = nil
				case "security-opt":
					state.Host.SecurityOpt = []string{"seccomp=unconfined"}
				case "group":
					state.Host.GroupAdd = []string{"0"}
				case "ports":
					state.Host.PortBindings = map[string]json.RawMessage{"443/tcp": json.RawMessage(`[]`)}
				case "sysctl":
					state.Host.Sysctls = map[string]json.RawMessage{"net.ipv4.ip_forward": json.RawMessage(`"1"`)}
				case "tmpfs":
					state.Host.Tmpfs = map[string]json.RawMessage{"/etc/glivela": json.RawMessage(`"rw"`)}
				case "device":
					state.Host.Devices = []json.RawMessage{json.RawMessage(`{}`)}
				case "gpu":
					state.Host.DeviceRequests = []json.RawMessage{json.RawMessage(`{}`)}
				case "mount-source":
					state.Mounts[0].Source += "-other"
				case "mount-rw":
					state.Mounts[0].RW = true
				case "mount-shadow":
					state.Mounts = append(state.Mounts, state.Mounts[0])
					state.Mounts[1].Destination += "/config.json"
				case "propagation":
					state.Mounts[0].Propagation = "rshared"
				case "user":
					state.Config.User = "0"
				case "network-mode":
					state.Host.NetworkMode = "none"
				case "userns":
					state.Host.UsernsMode = "container:other"
				case "extra-network":
					state.Networks["other"] = struct{ NetworkID string }{}
				case "network-id":
					if host {
						delete(state.Networks, "host")
						state.Networks["other"] = struct{ NetworkID string }{}
					} else {
						state.Networks[c.NetworkName] = struct{ NetworkID string }{strings.Repeat("d", 64)}
					}
				}
				err := c.verifyState(d, state)
				if (err == nil) != (fault == "none") {
					t.Fatalf("read-back accepted=%v, fault=%s", err == nil, fault)
				}
			})
		}
	}
}

func TestEntryContainerSnapshotIdentityAndRole(t *testing.T) {
	c, d, state := entryContainerFixture(t, true)
	base := c.Fingerprint()
	if base == "" || strings.Contains(base, c.ConfigurationDirectory) || strings.Contains(base, "PATH") {
		t.Fatal("missing or sensitive binding")
	}
	for _, change := range []func(*EntryContainer){func(x *EntryContainer) { x.ContainerID = strings.Repeat("e", 64) }, func(x *EntryContainer) { x.GID++ }, func(x *EntryContainer) { x.Environment = []string{"PATH=/other"} }, func(x *EntryContainer) { x.ConfigurationDirectory += "-other" }} {
		x := c
		change(&x)
		if x.Fingerprint() == base {
			t.Fatal("ownership change retained binding")
		}
	}
	if c.verifyState(artifact(1), state) == nil {
		t.Fatal("landing accepted as entry")
	}
	if c.Verify(context.Background(), artifact(1)) == nil {
		t.Fatal("wrong role reached Docker")
	}
	x := d.clone()
	x.Entry.RealityEndpoints[0].EntryID = "another-entry"
	if c.verifyState(x, state) == nil {
		t.Fatal("foreign entry accepted")
	}
	c.ContainerID = "short-id"
	if c.Fingerprint() != "" || c.Verify(context.Background(), d) == nil {
		t.Fatal("mutable name/short ID accepted")
	}
}

func TestEntryBridgeReadbackBindsActualNetworkIDAndInterface(t *testing.T) {
	c, _, _ := entryContainerFixture(t, false)
	fixture := func(id, name, driver, bridge string) []byte {
		raw, _ := json.Marshal(map[string]any{"Id": id, "Name": name, "Driver": driver, "Scope": "local", "Internal": false, "Ingress": false, "Options": map[string]string{"com.docker.network.bridge.name": bridge}})
		return raw
	}
	if c.verifyBridgeState(fixture(c.NetworkID, c.NetworkName, "bridge", c.Bridge)) != nil {
		t.Fatal("owned bridge rejected")
	}
	for _, raw := range [][]byte{fixture(strings.Repeat("e", 64), c.NetworkName, "bridge", c.Bridge), fixture(c.NetworkID, "other", "bridge", c.Bridge), fixture(c.NetworkID, c.NetworkName, "macvlan", c.Bridge), fixture(c.NetworkID, c.NetworkName, "bridge", "br-other"), append(fixture(c.NetworkID, c.NetworkName, "bridge", c.Bridge), []byte(` {}`)...)} {
		if c.verifyBridgeState(raw) == nil {
			t.Fatal("network recreation/driver/interface drift accepted")
		}
	}
	c.Bridge = "br-" + c.NetworkID[:12]
	if c.verifyBridgeState(fixture(c.NetworkID, c.NetworkName, "bridge", "")) != nil {
		t.Fatal("explicitly recorded default bridge rejected")
	}
}

func TestEntryInspectionParsingIsBoundedAndDoesNotLeakDiagnostics(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(`{} {}`), []byte(`{"State":"synthetic-secret"}`), []byte(strings.Repeat("x", (1<<20)+1))} {
		if _, err := decodeEntryContainer(raw); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("unsafe inspection parsing")
		}
	}
	var buffer entryDockerOutput
	if _, err := buffer.Write(make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte("x")); err == nil {
		t.Fatal("unbounded Docker output")
	}
}

func TestEntryContainerPreservesExplicitHY2HostAndBridgeBoundaries(t *testing.T) {
	_, ca, signer := identity(t, nil, nil, false)
	certificate, _, key := identity(t, ca, signer, true)
	privateDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []bool{false, true} {
		c, d, state := entryContainerFixture(t, host)
		plan := *d.Entry
		plan.HysteriaEndpoints = []glivela.HysteriaEndpoint{{ID: "hy2-example", EntryID: c.ApplicationID, InboundTag: "hy2-example", ListenPort: 443, AdvertiseHost: "entry.example.test", AdvertisePort: 443, ServerName: "127.0.0.1", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}))}}
		plan.Credentials[0].HysteriaAuth = "anonymous-hy2-auth"
		plan.Credentials[0].HysteriaIdentity = glivela.Identity(plan.Credentials[0].HysteriaAuth)
		d, err = NewEntryDesired(plan, *d.EntryNetwork)
		if err != nil {
			t.Fatal("anonymous HY2 fixture", err)
		}
		if host {
			state.Host.CapAdd = []string{"CAP_NET_BIND_SERVICE"}
		} else {
			state.Host.PortBindings = map[string]json.RawMessage{"443/udp": json.RawMessage(`[{"HostIp":"0.0.0.0","HostPort":"443"}]`)}
		}
		if err := c.verifyState(d, state); err != nil {
			t.Fatalf("authorized HY2 boundary rejected: host=%v %v", host, err)
		}
		if host {
			state.Host.PortBindings = map[string]json.RawMessage{"443/udp": json.RawMessage(`[{"HostIp":"0.0.0.0","HostPort":"443"}]`)}
		} else {
			state.Host.PortBindings["443/udp"] = json.RawMessage(`[{"HostIp":"0.0.0.0","HostPort":"444"}]`)
		}
		if c.verifyState(d, state) == nil {
			t.Fatal("unauthorized UDP mapping accepted")
		}
	}
}
