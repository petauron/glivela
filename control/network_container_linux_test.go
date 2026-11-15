//go:build linux

package control

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestContainerBufferText(t *testing.T) {
	text := networkText(NetworkSnapshot{BufferOnly: true, Receive: [3]int64{4096, 131072, 32 << 20}, Send: [3]int64{4096, 16384, 8 << 20}, ReceiveMax: 8 << 20, SendMax: 8 << 20})
	for _, forbidden := range []string{"congestion_control", "default_qdisc", "tcp_mem"} {
		if strings.Contains(text, forbidden) {
			t.Fatal(text)
		}
	}
	if strings.Count(text, " = ") != 2 {
		t.Fatal(text)
	}
}

func TestLXCBufferLifecycle(t *testing.T) {
	if os.Getenv("GLIVELA_LXC_LAB") != "1" {
		t.Skip("requires dedicated isolated LXC")
	}
	ctx := context.Background()
	dir, err := os.MkdirTemp("/root", "glivela-buffer-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if _, err := isolatedNetworkNamespace(); err != nil {
		t.Fatal(err)
	}
	before := inspectNetwork(ctx, dir)
	if !before.BufferOnly || !before.CanApply || before.TCPBudget != nil {
		t.Fatalf("%+v", before)
	}
	command := func(action string, snap NetworkSnapshot) NetworkReport {
		return executeNetwork(ctx, dir, NetworkCommand{ID: action + time.Now().String(), Action: action, Expected: snap.Fingerprint, BufferBytes: networkAutoBuffer(snap), ExpiresAt: time.Now().Add(time.Minute)})
	}
	applied := command("apply", before)
	if applied.Result.State != "succeeded" {
		t.Fatalf("%+v", applied)
	}
	defer func() {
		r := command("restore", inspectNetwork(ctx, dir))
		if r.Result.State != "succeeded" {
			t.Errorf("restore: %+v", r)
		}
	}()
	target := applied.Snapshot
	if target.Congestion != before.Congestion || target.QdiscFingerprint != before.QdiscFingerprint || !target.CanRestore || target.Send[0] != before.Send[0] || target.Send[1] != before.Send[1] {
		t.Fatal("unrelated value changed")
	}
	raw, err := os.ReadFile(networkSysctlFile)
	if err != nil || string(raw) != networkText(target) {
		t.Fatalf("persistence: %v", err)
	}
	r := command("restore", target)
	if r.Result.State != "succeeded" || !sameNetworkValues(r.Snapshot, before) {
		t.Fatalf("restore: %+v", r)
	}
	if _, err = os.Stat(networkSysctlFile); !os.IsNotExist(err) {
		t.Fatal("persistent file remains")
	}
	// Verify repeated application uses a fresh first recovery snapshot.
	again := command("apply", r.Snapshot)
	if again.Result.State != "succeeded" {
		t.Fatalf("reapply: %+v", again)
	}
	t.Logf("container apply/readback/restore/reapply: receive=%v send=%v", target.Receive, target.Send)
}
