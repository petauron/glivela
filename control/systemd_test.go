package control

import "testing"

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
		func(d *SystemdDriver) { d.WorkerUID = 0 },
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
