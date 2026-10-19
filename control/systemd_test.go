package control

import (
	"encoding/json"
	"os/user"
	"strings"
	"testing"
)

func TestSystemdInstallationIdentityIsExplicitAndScoped(t *testing.T) {
	d := SystemdDriver{Unit: "example-app-worker.service", WorkerUser: "example-worker", WorkerUID: 1234, Interface: "mesh0"}
	path, err := d.installationNames()
	if err != nil || path != "/etc/systemd/system/example-app-worker.service" {
		t.Fatal("local installation names rejected", path, err)
	}
	for _, change := range []func(*SystemdDriver){
		func(d *SystemdDriver) { d.Unit = "" },
		func(d *SystemdDriver) { d.Unit = "../sshd.service" },
		func(d *SystemdDriver) { d.Unit = "worker@other.service" },
		func(d *SystemdDriver) { d.Unit = "--help.service" },
		func(d *SystemdDriver) { d.Unit = "worker.service\n" },
		func(d *SystemdDriver) { d.WorkerUser = "root" },
		func(d *SystemdDriver) { d.WorkerUser = "" },
	} {
		bad := d
		change(&bad)
		if _, err := bad.installationNames(); err == nil {
			t.Fatalf("unsafe installation identity accepted: %#v", bad)
		}
	}
	for _, change := range []func(*SystemdDriver){
		func(d *SystemdDriver) { d.Unit = "other-worker.service" },
		func(d *SystemdDriver) { d.WorkerUser = "other-worker" },
		func(d *SystemdDriver) { d.WorkerUID++ },
		func(d *SystemdDriver) { d.Interface = "mesh1" },
	} {
		other := d
		change(&other)
		if other.Binding() == d.Binding() {
			t.Fatal("ownership change would silently reuse runtime journal")
		}
	}
}

func TestSystemdWorkerUIDComesFromLocalAccount(t *testing.T) {
	d := SystemdDriver{Unit: "example-worker.service", WorkerUser: "example-worker"}
	resolved, err := d.bindWorker(&user.User{Username: d.WorkerUser, Uid: "1234", Gid: "1234"})
	if err != nil || resolved.WorkerUID != 1234 {
		t.Fatal("local account identity not bound", err)
	}
	for _, worker := range []*user.User{
		nil,
		{Username: "other", Uid: "1234", Gid: "1234"},
		{Username: d.WorkerUser, Uid: "0", Gid: "1234"},
		{Username: d.WorkerUser, Uid: "1234", Gid: "0"},
		{Username: d.WorkerUser, Uid: "4294967296", Gid: "1234"},
	} {
		if _, err := d.bindWorker(worker); err == nil {
			t.Fatal("invalid account accepted")
		}
	}
	raw, err := json.Marshal(resolved)
	if err != nil || strings.Contains(string(raw), "workerUid") {
		t.Fatal("allocated UID leaked into bootstrap configuration", err)
	}
	decoder := json.NewDecoder(strings.NewReader(`{"workerUid":1234}`))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) == nil {
		t.Fatal("bootstrap may not override the local UID")
	}
}

func TestSystemdLoadedUnitMustMatchOwnedInstallation(t *testing.T) {
	d := SystemdDriver{Unit: "example-worker.service", WorkerUser: "example-worker"}
	raw := "LoadState=loaded\nFragmentPath=/etc/systemd/system/example-worker.service\nDropInPaths=\nNeedDaemonReload=no\nUser=example-worker\n"
	if !d.loadedUnitMatches(raw) || !d.loadedUnitMatches(strings.TrimSuffix(raw, "\n")) {
		t.Fatal("matching loaded unit refused")
	}
	for name, value := range map[string]string{
		"not loaded":    strings.Replace(raw, "LoadState=loaded", "LoadState=not-found", 1),
		"alias":         strings.Replace(raw, "/etc/systemd/system/example-worker.service", "/usr/lib/systemd/system/other.service", 1),
		"override":      strings.Replace(raw, "DropInPaths=", "DropInPaths=/etc/systemd/system/example-worker.service.d/override.conf", 1),
		"stale":         strings.Replace(raw, "NeedDaemonReload=no", "NeedDaemonReload=yes", 1),
		"root":          strings.Replace(raw, "User=example-worker", "User=root", 1),
		"implicit root": strings.Replace(raw, "User=example-worker", "User=", 1),
		"missing user":  strings.Replace(raw, "User=example-worker\n", "", 1),
		"duplicate":     raw + "LoadState=loaded\n",
		"unknown":       raw + "Unexpected=value\n",
		"empty":         "",
	} {
		t.Run(name, func(t *testing.T) {
			if d.loadedUnitMatches(value) {
				t.Fatal("unverified loaded identity accepted")
			}
		})
	}
}
