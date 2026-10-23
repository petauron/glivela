package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/petauron/glivela/control"
)

func TestLiveMaintenanceSerializesWithoutStoppingManager(t *testing.T) {
	ctx := context.Background()
	entered, finish := make(chan struct{}), make(chan struct{})
	m := &liveMaintenance{directory: t.TempDir(), run: func(_ context.Context, action string) error {
		if action != "prepare" {
			return errors.New("unexpected operation")
		}
		close(entered)
		<-finish
		return nil
	}}
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/prepare", nil))
	}()
	<-entered
	// An unconfigured node would fail if called. Drainage excludes normal
	// reconciliation without stopping the manager or its independent monitors.
	if err := m.step(ctx, control.NodeRunner{}); err != nil {
		t.Fatal("reconciliation ran during drain", err)
	}
	busy := httptest.NewRecorder()
	m.ServeHTTP(busy, httptest.NewRequest(http.MethodPost, "/complete", nil))
	if busy.Code != http.StatusConflict {
		t.Fatal("concurrent maintenance accepted")
	}
	close(finish)
	<-done
	if response.Code != http.StatusNoContent {
		t.Fatal("maintenance failed")
	}
	checkpoint := filepath.Join(m.directory, "transport-prepared.json")
	if err := os.WriteFile(checkpoint, []byte("retained checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.step(ctx, control.NodeRunner{}); err != nil {
		t.Fatal("sealed checkpoint was reconciled", err)
	}
	if err := os.Remove(checkpoint); err != nil {
		t.Fatal(err)
	}
	if m.step(ctx, control.NodeRunner{}) == nil {
		t.Fatal("ordinary reconciliation did not resume")
	}
}

func TestLiveMaintenanceRejectsUnsupportedRequestsAndDoesNotReportFailureAsSuccess(t *testing.T) {
	calls := 0
	m := &liveMaintenance{run: func(context.Context, string) error { calls++; return errors.New("private detail") }}
	for _, target := range []string{"/execute", "/prepare?force=true", "/"} {
		w := httptest.NewRecorder()
		m.ServeHTTP(w, httptest.NewRequest(http.MethodPost, target, nil))
		if w.Code != http.StatusBadRequest || calls != 0 {
			t.Fatal("unsupported operation accepted")
		}
	}
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/cancel", nil))
	if w.Code != http.StatusConflict || calls != 1 {
		t.Fatal("failed recovery reported as success")
	}
	if w.Body.String() == "private detail" {
		t.Fatal("private error leaked")
	}
}
