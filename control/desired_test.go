package control

import (
	"context"
	"testing"
)

func TestDesiredBindsPolicyToConfig(t *testing.T) {
	for _, change := range []func(*Desired){
		func(d *Desired) { d.Landing.Revision++ },
		func(d *Desired) { d.Landing.Sources[0].TCPOnly = true },
		func(d *Desired) { d.Landing.Sources = nil },
		func(d *Desired) { d.Landing.EgressIP = "192.168.50.3" },
		func(d *Desired) { d.Landing.Address = "100.64.0.4" },
	} {
		d := artifact(1)
		change(&d)
		if d.Validate() == nil {
			t.Fatal("policy mismatch accepted")
		}
	}
	d := artifact(1)
	copy := d.clone()
	copy.Landing.Sources[0].TCPOnly = true
	copy.Config[0] = 'x'
	if d.Validate() != nil {
		t.Fatal("clone mutated original")
	}
}

func TestRollbackRestoresPolicyTogetherWithConfiguration(t *testing.T) {
	r, driver := nativeFixture(t)
	ctx := context.Background()
	first := artifact(1)
	if err := r.Apply(ctx, first); err != nil {
		t.Fatal(err)
	}
	plan := artifact(2).Landing
	plan.Sources[0].TCPOnly = true
	next, err := NewDesired(*plan)
	if err != nil {
		t.Fatal(err)
	}
	driver.failHealth = 1
	if r.Apply(ctx, next) == nil {
		t.Fatal("failed health accepted")
	}
	if driver.active.Revision != 1 || driver.active.Landing.Sources[0].TCPOnly || driver.prior == nil || driver.prior.Revision != 2 || !driver.prior.Landing.Sources[0].TCPOnly {
		t.Fatal("restoration lost exact old/new firewall policies")
	}
	state, err := r.journal()
	if err != nil || state.Current.Landing.Sources[0].TCPOnly || state.Candidate != nil {
		t.Fatal("journal did not restore policy")
	}
}

func TestRuntimeBindingChangeFailsClosed(t *testing.T) {
	r, driver := nativeFixture(t)
	if err := r.Apply(context.Background(), artifact(1)); err != nil {
		t.Fatal(err)
	}
	driver.binding = "different-user-or-interface"
	if r.Recover(context.Background()) == nil {
		t.Fatal("changed local ownership accepted")
	}
	if r.Apply(context.Background(), artifact(2)) == nil || driver.starts != 1 {
		t.Fatal("changed binding disturbed service")
	}
}
