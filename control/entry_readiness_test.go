package control

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/petauron/glivela"
)

func TestEntryReadinessGenerationFence(t *testing.T) {
	var gate entryReadiness
	generation := "process-1:config-1"
	identity := func() (string, error) { return generation, nil }
	calls := 0
	probe := func(context.Context) error { calls++; return nil }
	if err := gate.check(context.Background(), identity, probe); err != nil {
		t.Fatal(err)
	}
	if err := gate.check(context.Background(), identity, probe); err != nil || calls != 1 {
		t.Fatal("same generation was not reused", err, calls)
	}
	generation = "process-2:config-1"
	if err := gate.check(context.Background(), identity, probe); err != nil || calls != 2 {
		t.Fatal("restart did not recheck", err, calls)
	}
	generation = "process-2:config-2"
	if err := gate.check(context.Background(), identity, func(context.Context) error { return errors.New("HTTPS failed") }); err == nil || gate.accepted != "" {
		t.Fatal("failed probe became ready")
	}
	if err := gate.check(context.Background(), identity, func(context.Context) error { generation = "process-3:config-2"; return nil }); err == nil || gate.accepted != "" {
		t.Fatal("restart during probe accepted")
	}
	if err := gate.check(context.Background(), identity, probe); err != nil {
		t.Fatal(err)
	}
	if err := gate.check(context.Background(), func() (string, error) { return "", errors.New("stopped") }, probe); err == nil || gate.accepted != "" {
		t.Fatal("stopped process retained readiness")
	}
}

func TestEntryRuntimeReadinessProbeFailure(t *testing.T) {
	runtime, driver, _, desired := entryDriverFixture(t)
	driver.readinessProbe = func(context.Context, Desired) error { return errors.New("TLS not ready") }
	if err := runtime.Apply(context.Background(), desired); err == nil {
		t.Fatal("apply succeeded without HTTPS readiness")
	}
	if driver.readiness.accepted != "" {
		t.Fatal("failed apply cached readiness")
	}
}

func TestEntryReadinessRestartRevokesRuntimeReceipt(t *testing.T) {
	runtime, driver, fixture, desired := entryDriverFixture(t)
	if err := runtime.Apply(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	driver.readinessProbe = func(context.Context, Desired) error {
		t.Fatal("running worker repeated external probe")
		return errors.New("target down")
	}
	for range 3 {
		observation, err := runtime.Inspect(context.Background())
		if err != nil || !observation.RuntimeReady {
			t.Fatal("running worker lost accepted readiness", err)
		}
	}
	fixture.state.State.Pid++
	driver.readinessProbe = func(context.Context, Desired) error { return errors.New("initializing") }
	observation, err := runtime.Inspect(context.Background())
	if err != nil || observation.RuntimeReady {
		t.Fatalf("restart retained ready receipt: %#v %v", observation, err)
	}
	driver.readinessProbe = func(context.Context, Desired) error { return nil }
	observation, err = runtime.Inspect(context.Background())
	if err != nil || !observation.RuntimeReady {
		t.Fatalf("readiness did not recover: %#v %v", observation, err)
	}
}

func TestNativeWarmupSelectsOwnedListenerWithoutChangingAdvertisement(t *testing.T) {
	for _, tc := range []struct{ listen, want string }{{"100.64.0.20", "100.64.0.20"}, {"2001:db8::20", "2001:db8::20"}, {"0.0.0.0", "127.0.0.1"}, {"::", "::1"}} {
		original := glivela.RealityEndpoint{EntryID: "entry-test", ListenAddress: tc.listen, ListenPort: 10443, AdvertiseHost: "outside.example.test", AdvertisePort: 443, ServerNames: []string{"www.apple.com"}, PublicKey: "retained-public-key"}
		desired := Desired{Entry: &glivela.XrayPlan{RealityEndpoints: []glivela.RealityEndpoint{original}}}
		plan, err := nativeWarmupPlan(desired)
		if err != nil {
			t.Fatal(err)
		}
		if plan.RealityEndpoints[0].AdvertiseHost != tc.want || plan.RealityEndpoints[0].AdvertisePort != 10443 {
			t.Fatal("warmup used public frontend instead of owned listener")
		}
		if !reflect.DeepEqual(desired.Entry.RealityEndpoints[0], original) || plan.RealityEndpoints[0].PublicKey != original.PublicKey || !reflect.DeepEqual(plan.RealityEndpoints[0].ServerNames, original.ServerNames) {
			t.Fatal("warmup changed published identity")
		}
	}
	for _, e := range []glivela.RealityEndpoint{{ListenAddress: "outside.example.test", ListenPort: 443}, {ListenAddress: "127.0.0.1", ListenPort: 0}, {ListenAddress: "127.0.0.1", ListenPort: 65536}} {
		if _, err := nativeWarmupPlan(Desired{Entry: &glivela.XrayPlan{RealityEndpoints: []glivela.RealityEndpoint{e}}}); err == nil {
			t.Fatal("unbound warmup destination accepted")
		}
	}
}
