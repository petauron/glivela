//go:build linux

package landing

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

// No host networking, Docker access, or public test endpoint is involved.
// CI invokes this binary in a new root network namespace, as for landing policy.
func TestKernelEntryGateLifecycle(t *testing.T) {
	if os.Getenv("GLIVELA_KERNEL_FIREWALL_TEST") != "1" {
		t.Skip("isolated Linux namespace required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	initial, initialErr := os.Readlink("/proc/1/ns/net")
	if err != nil || initialErr != nil || current == initial || os.Geteuid() != 0 {
		t.Fatal("refusing test outside a separate root network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	peer := PeerIdentity{ID: "anonymous-entry-gate", PublicKey: "nodekey:anonymous", Address: "100.64.0.8"}
	bridge, _ := NewBridgeGate(peer, "br-fixture", 1)
	host, _ := NewHostGate(peer, 12345, 1)
	for _, gate := range []*TrafficGate{bridge, host} {
		t.Run(gate.scopeChain(), func(t *testing.T) {
			if err := gate.Install(ctx); err != nil {
				t.Fatal("install", err)
			}
			until := time.Now().Add(5 * time.Second)
			if err := gate.renew(ctx, until); err != nil {
				t.Fatal("renew", err)
			}
			if gate.Remove(ctx) == nil {
				t.Fatal("removed live policy")
			}
			<-time.After(time.Until(until))
			document, err := gate.snapshot(ctx)
			if err != nil || len(gate.elements(document)) != 0 {
				t.Fatal("kernel retained expired permission", err)
			}
			if err := gate.renew(ctx, time.Now().Add(AllowLifetime)); err != nil {
				t.Fatal(err)
			}
			if err := gate.Install(ctx); err != nil {
				t.Fatal(err)
			}
			document, err = gate.snapshot(ctx)
			if err != nil || len(gate.elements(document)) != 0 {
				t.Fatal("restart retained old lease", err)
			}
			var replacement, unrelated *TrafficGate
			otherPeer := peer
			otherPeer.Address = "100.64.0.9"
			otherPeer.ID = "anonymous-other"
			if gate.gid == 0 {
				replacement, _ = NewBridgeGate(peer, gate.bridge, 2)
				unrelated, _ = NewBridgeGate(otherPeer, gate.bridge, 1)
			} else {
				replacement, _ = NewHostGate(peer, gate.gid, 2)
				unrelated, _ = NewHostGate(otherPeer, gate.gid, 1)
			}
			if err := unrelated.Install(ctx); err != nil {
				t.Fatal(err)
			}
			before, err := runNFT(ctx, nil, "--json", "list", "table", "inet", unrelated.table)
			if err != nil {
				t.Fatal(err)
			}
			if err := replacement.Install(ctx); err != nil {
				t.Fatal(err)
			}
			if err := replacement.renew(ctx, time.Now().Add(AllowLifetime)); err != nil {
				t.Fatal(err)
			}
			if err := replacement.RemoveClosedConflicts(ctx); err != nil {
				t.Fatal(err)
			}
			document, err = replacement.snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if found, err := gate.validate(document); err != nil || found {
				t.Fatal("closed older revision survived", err)
			}
			after, err := runNFT(ctx, nil, "--json", "list", "table", "inet", unrelated.table)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("another peer's policy changed", err)
			}
			if err := replacement.Block(ctx); err != nil {
				t.Fatal(err)
			}
			if err := replacement.Remove(ctx); err != nil {
				t.Fatal(err)
			}
			if err := unrelated.Remove(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
