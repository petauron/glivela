package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/petauron/glivela/control"
)

// One root-only local socket, no public listener or generic execution API.
// The manager retains its directory lease and health monitors during drainage.
type liveMaintenance struct {
	mu        sync.Mutex
	directory string
	run       func(context.Context, string) error
	server    *http.Server
	listener  net.Listener
}

func startLiveMaintenance(ctx context.Context, runtime *control.NativeRuntime, client *control.Client) (*liveMaintenance, error) {
	path := filepath.Join(runtime.Directory, "maintenance.sock")
	info, err := os.Lstat(runtime.Directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || os.Geteuid() != 0 {
		return nil, errors.New("private root maintenance directory required")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nil, errors.New("root-owned maintenance directory required")
	}
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
			return nil, errors.New("unexpected maintenance path")
		}
		// Caller already holds the exclusive state-directory lease. Only its
		// own stale socket may remain after a manager crash.
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	m := &liveMaintenance{directory: runtime.Directory, listener: listener}
	m.run = func(ctx context.Context, action string) error {
		switch action {
		case "prepare":
			tail, err := runtime.PrepareTransportTail(ctx)
			if err != nil {
				return err
			}
			if err := client.RecordTransportTail(ctx, tail); err != nil {
				return err
			}
			return runtime.StopPreparedTransport(ctx)
		case "complete":
			return runtime.CompleteTransport(ctx, client)
		case "cancel":
			return runtime.CancelTransport(ctx, client)
		}
		return errors.New("unknown maintenance operation")
	}
	m.server = &http.Server{Handler: m, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 7 * time.Minute, MaxHeaderBytes: 1024, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { _ = m.server.Serve(listener) }()
	return m, nil
}

func (m *liveMaintenance) Close() { _ = m.server.Close() }

func (m *liveMaintenance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.ContentLength != 0 || (r.URL.Path != "/prepare" && r.URL.Path != "/complete" && r.URL.Path != "/cancel") {
		http.Error(w, "unsupported maintenance request", http.StatusBadRequest)
		return
	}
	if !m.mu.TryLock() {
		http.Error(w, "maintenance busy", http.StatusConflict)
		return
	}
	defer m.mu.Unlock()
	timeout := time.Minute
	if r.URL.Path == "/prepare" {
		timeout = 6 * time.Minute
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	if err := m.run(ctx, r.URL.Path[1:]); err != nil {
		http.Error(w, "maintenance unconfirmed; retain checkpoint and investigate", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *liveMaintenance) step(ctx context.Context, node control.NodeRunner) error {
	if !m.mu.TryLock() {
		return nil
	}
	defer m.mu.Unlock()
	if _, err := os.Lstat(filepath.Join(m.directory, "transport-prepared.json")); err == nil {
		return nil // Only explicit completion/cancellation may apply this revision.
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return node.Step(ctx)
}

func requestLiveMaintenance(ctx context.Context, directory, action string) error {
	path := filepath.Join(directory, "maintenance.sock")
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("running manager maintenance socket required; do not stop it before drainage")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return errors.New("untrusted maintenance socket")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 7 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/"+action, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("maintenance reply unavailable; inspect checkpoint before retry")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode != http.StatusNoContent {
		return errors.New("live maintenance not confirmed; retain state for recovery")
	}
	return nil
}
