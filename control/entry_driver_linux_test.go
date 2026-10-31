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
	if err := r.Apply(ctx, desired); err == nil {
		t.Fatal("startup succeeded without private route proof")
	}
	if worker.starts != 1 || worker.stops < 1 {
		t.Fatal("failed startup left worker running")
	}
	gates, err := d.gates(desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, gate := range gates {
		if err := gate.Verify(ctx); err != nil {
			t.Fatal("failed startup lost closed fence", err)
		}
	}
	for range 3 {
		receipt, err := r.Inspect(ctx)
		if err == nil && receipt.RuntimeReady {
			t.Fatal("failed startup became ready")
		}
	}
	// Separately retain unchanged native worker resume coverage. The fixture
	// simulates REALITY warmup; the earlier failure uses real kernel fences.
	native, driver, running, want := entryDriverFixture(t)
	if err := native.Apply(ctx, want); err != nil {
		t.Fatal(err)
	}
	if err := driver.Close(ctx); err != nil {
		t.Fatal(err)
	}
	resumed := &EntryDriver{Container: driver.Container, Directory: driver.Directory, binary: driver.binary, binarySHA256: driver.binarySHA256, docker: driver.docker, process: driver.process, readinessProbe: driver.readinessProbe}
	defer resumed.Close(context.Background())
	restarted := &NativeRuntime{Directory: native.Directory, Driver: resumed}
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if running.starts != 1 || running.stops != 0 {
		t.Fatal("unchanged native resume restarted worker")
	}

}
