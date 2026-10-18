//go:build linux

package control

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/petauron/glivela/landing"
)

type unavailableEntryLink struct{}

func (unavailableEntryLink) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("anonymous private link unavailable")
}

// The nftables policy is real in an isolated namespace. Docker, process
// identity/listener acceptance and the private network API are simulated. This
// is explicitly NOT an actual container/adoption or successful-route test.
func TestKernelEntryDriverBlockedPeerAndNodeResume(t *testing.T) {
	if os.Getenv("GLIVELA_ENTRY_RUNTIME_KERNEL_TEST") != "1" {
		t.Skip("isolated Linux namespace required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	initial, initialErr := os.Readlink("/proc/1/ns/net")
	if err != nil || initialErr != nil || current == initial || os.Geteuid() != 0 {
		t.Fatal("refusing test outside a separate root network namespace")
	}
	r, d, worker, entry := entryDriverFixture(t)
	desired := withRoutedEntry(t, entry)
	links := func() *landing.LinkChecker {
		return &landing.LinkChecker{HTTPClient: &http.Client{Transport: unavailableEntryLink{}}}
	}
	d.links = links
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	defer d.Close(context.Background())
	if err := r.Apply(ctx, desired); err != nil {
		t.Fatal("gated owned configuration application", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for d.PeerStatus()["landing-example"].Reason != "local_status_unavailable" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	status := d.PeerStatus()["landing-example"]
	if status.State != "blocked" || status.Reason != "local_status_unavailable" || !status.AllowedUntil.IsZero() {
		t.Fatal("missing private proof opened a peer gate")
	}
	if worker.starts != 1 || worker.stops != 0 {
		t.Fatal("peer failure restarted shared worker")
	}
	for range 3 {
		receipt, err := r.Inspect(ctx)
		if err != nil || !receipt.RuntimeReady {
			t.Fatal("ordinary blocked peer became global process failure", err)
		}
		if receipt.EntryHealth == nil || receipt.EntryHealth.SampledAt.IsZero() || receipt.EntryHealth.Peers["landing-example"].Status.State != "blocked" || validateEntryHealth(desired, receipt.EntryHealth) != nil {
			t.Fatal("blocked peer observation missing or malformed")
		}
	}
	if worker.starts != 1 || worker.stops != 0 {
		t.Fatal("health polling mutated worker")
	}
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if d.EntryHealth(desired) != nil {
		t.Fatal("stopped monitor retained health evidence")
	}
	// Simulate only a Glivela node-program restart, not a Docker or host boot.
	// A matching running worker/configuration must not be reset needlessly.
	resumed := &EntryDriver{Container: d.Container, Directory: d.Directory, binary: d.binary, binarySHA256: d.binarySHA256, docker: d.docker, process: d.process, links: links}
	defer resumed.Close(context.Background())
	restarted := &NativeRuntime{Directory: r.Directory, Driver: resumed}
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal("unchanged worker resume", err)
	}
	if worker.starts != 1 || worker.stops != 0 {
		t.Fatal("node-program restart reset unchanged Xray")
	}
	if err := resumed.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
