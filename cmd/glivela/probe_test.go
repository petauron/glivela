package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/petauron/glivela/control"
)

func TestRouteCommandReportsFailureForExactOperation(t *testing.T) {
	p := control.RouteProbe{AttemptID: "attempt-example", SnapshotID: "snapshot-a", EntryID: "entry-a", LandingID: "landing-a", Revision: 7, ConfigSHA256: strings.Repeat("a", 64), SOCKSAddress: "127.0.0.1:1080", Target: "https://check.example.invalid/exit", ExpectedExit: "203.0.113.9"}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if verifyRoute(ctx, path, &output) == nil {
		t.Fatal("cancelled probe succeeded")
	}
	var result control.RouteProbeResult
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Passed || result.TLSVerified || result.SnapshotID != p.SnapshotID || result.Revision != 7 {
		t.Fatal("failure was not associated with exact request")
	}
	if strings.Contains(output.String(), p.Target) {
		t.Fatal("raw target unnecessarily exposed in receipt")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if verifyRoute(ctx, path, &output) == nil || output.Len() != 0 {
		t.Fatal("unsafe request accepted")
	}
}
