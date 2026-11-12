//go:build linux

package landing

import (
	"context"
	"os"
	"testing"
)

func TestEntryFirewallRoundSafety(t *testing.T) {
	if os.Getenv("GLIVELA_KERNEL_FIREWALL_TEST") != "1" {
		t.Skip("isolated network namespace required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	initial, e := os.Readlink("/proc/1/ns/net")
	if err != nil || e != nil || current == initial || os.Geteuid() != 0 {
		t.Fatal("refusing non-isolated firewall mutation")
	}
	ctx := context.Background()
	p := EntryFirewall{UID: 1234, Revision: 201, DNS: []string{"1.1.1.1"}}
	if err := p.Install(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	p.DNS = []string{"1.0.0.1"}
	if err := p.Verify(ctx); err != nil {
		t.Fatal("DNS transition readback", err)
	}
	if err := p.Verify(ctx); err != nil {
		t.Fatal("next independent observation", err)
	}
	table, _ := p.identity()
	if _, err := runNFT(ctx, nil, "flush", "chain", "inet", table, "destinations"); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(ctx); err == nil {
		t.Fatal("foreign policy change accepted")
	}
	if _, err := runNFT(ctx, nil, "delete", "table", "inet", table); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(ctx); err == nil {
		t.Fatal("missing owned table accepted")
	}
}
