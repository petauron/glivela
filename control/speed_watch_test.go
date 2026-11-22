package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAdminLinkSpeedsSurvivesTightServerWriteTimeout(t *testing.T) {
	_, ca, key := identity(t, nil, nil, false)
	serverCert, _, _ := identity(t, ca, key, true)
	nodeTLS, nodeCert, _ := identity(t, ca, key, false)
	adminTLS, adminLeaf, _ := identity(t, ca, key, false)
	_ = nodeTLS

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	s := store(t)
	s.speedWatchTimeout = 250 * time.Millisecond
	if err := s.Put(Node{ID: "node-one", CertificateID: CertificateID(nodeCert), Desired: artifact(1)}); err != nil {
		t.Fatal(err)
	}
	app, err := NewServer("127.0.0.1:0", s, serverCert, roots, []string{CertificateID(adminLeaf)})
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(app.Handler)
	listener.EnableHTTP2 = true
	listener.TLS = app.TLSConfig.Clone()
	listener.Config.HTTP2 = app.HTTP2
	listener.Config.ReadTimeout = 5 * time.Second
	listener.Config.WriteTimeout = 100 * time.Millisecond
	listener.StartTLS()
	defer listener.Close()

	for _, tc := range []struct {
		name      string
		wantProto int
		transport func(*tls.Config) *http.Transport
	}{
		{
			name:      "http1",
			wantProto: 1,
			transport: func(tlsConfig *tls.Config) *http.Transport {
				return &http.Transport{
					Proxy:             nil,
					DialContext:       (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
					DisableKeepAlives: true,
					TLSClientConfig:   tlsConfig,
				}
			},
		},
		{
			name:      "http2",
			wantProto: 2,
			transport: func(tlsConfig *tls.Config) *http.Transport {
				return &http.Transport{
					Proxy:             nil,
					ForceAttemptHTTP2: true,
					TLSClientConfig:   tlsConfig,
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlsConfig := &tls.Config{
				MinVersion:   tls.VersionTLS13,
				RootCAs:      roots,
				Certificates: []tls.Certificate{adminTLS},
			}
			client := &http.Client{Timeout: 5 * time.Second, Transport: tc.transport(tlsConfig)}
			defer client.CloseIdleConnections()

			post := func(body []byte) SpeedList {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, listener.URL+"/v1/admin/link-speeds", bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("link-speeds request failed: %v", err)
				}
				defer resp.Body.Close()
				if resp.ProtoMajor != tc.wantProto {
					t.Fatalf("expected HTTP/%d, got HTTP/%d", tc.wantProto, resp.ProtoMajor)
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("expected HTTP 200, got %d", resp.StatusCode)
				}
				var list SpeedList
				if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
					t.Fatalf("decode speed list: %v", err)
				}
				return list
			}

			snapshot := post([]byte("{}"))
			if len(snapshot.Channels) != 1 || snapshot.Channels[0].ID != "node-one" {
				t.Fatalf("unexpected channels: %+v", snapshot.Channels)
			}
			waitBody, err := json.Marshal(map[string]string{"afterRevision": strconv.FormatUint(snapshot.Revision, 10)})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			waited := post(waitBody)
			if elapsed := time.Since(started); elapsed < 200*time.Millisecond {
				t.Fatalf("expected bounded wait beyond WriteTimeout, returned in %v", elapsed)
			}
			if waited.Revision != snapshot.Revision || len(waited.Channels) != 1 || waited.Channels[0].ID != "node-one" {
				t.Fatalf("unexpected waited list: %+v", waited)
			}
		})
	}
}

func TestWatchSpeedsDoesNotBlockOnStoreMutex(t *testing.T) {
	_, ca, key := identity(t, nil, nil, false)
	_, cert1, _ := identity(t, ca, key, false)
	_, cert2, _ := identity(t, ca, key, false)
	s := store(t)
	s.speedWatchTimeout = 80 * time.Millisecond
	if err := s.Put(Node{ID: "node-one", CertificateID: CertificateID(cert1), Desired: artifact(1)}); err != nil {
		t.Fatal(err)
	}

	// Simulate an unrelated Store.mu writer (e.g., hourly backup or fsync burst).
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	snapshot, err := s.WatchSpeeds(ctx, nil)
	if err != nil {
		t.Fatalf("snapshot failed while Store.mu held: %v", err)
	}
	if len(snapshot.Channels) != 1 || snapshot.Channels[0].ID != "node-one" {
		t.Fatalf("unexpected snapshot channels: %+v", snapshot.Channels)
	}
	rev := snapshot.Revision
	waited, err := s.WatchSpeeds(ctx, &rev)
	if err != nil {
		t.Fatalf("long-poll failed while Store.mu held: %v", err)
	}
	if waited.Revision != rev || len(waited.Channels) != 1 {
		t.Fatalf("unexpected waited result: %+v", waited)
	}

	s.mu.Unlock()
	locked = false

	// Enrolling a second node updates the detached watch snapshot on commit.
	if err := s.Put(Node{ID: "node-two", CertificateID: CertificateID(cert2), Desired: artifact(1)}); err != nil {
		t.Fatal(err)
	}
	updated, err := s.WatchSpeeds(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Channels) != 2 || updated.Channels[0].ID != "node-one" || updated.Channels[1].ID != "node-two" {
		t.Fatalf("node commit not reflected in watch channels: %+v", updated.Channels)
	}

	s.speedViewMu.Lock()
	s.speedWatchTimeout = 2 * time.Second
	s.speedViewMu.Unlock()

	cancelCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, watchErr := s.WatchSpeeds(cancelCtx, &updated.Revision)
		done <- watchErr
	}()
	time.Sleep(25 * time.Millisecond)
	stop()
	select {
	case watchErr := <-done:
		if !errors.Is(watchErr, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", watchErr)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled WatchSpeeds did not return promptly")
	}
}

func TestWatchSpeedsExpiresOverdueJobAndWakesOnFault(t *testing.T) {
	t.Run("expires-overdue-job", func(t *testing.T) {
		_, ca, key := identity(t, nil, nil, false)
		_, cert, _ := identity(t, ca, key, false)
		fingerprint := CertificateID(cert)
		s := store(t)
		s.speedWatchTimeout = 2 * time.Second
		if err := s.Put(Node{ID: "node-one", CertificateID: fingerprint, Desired: artifact(1)}); err != nil {
			t.Fatal(err)
		}
		id := uuid.NewString()
		job := cleanupTask(id, fingerprint)
		job.Phase = "receiver"
		job.View.State = "queued"
		job.View.StartedAt = time.Now().UTC().Add(-speedLease + 60*time.Millisecond)
		s.mu.Lock()
		s.speedJobs = map[string]*speedRecord{id: job}
		if err := s.saveSpeedLocked(); err != nil {
			s.mu.Unlock()
			t.Fatal(err)
		}
		rev := s.speedRevision
		s.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		started := time.Now()
		list, err := s.WatchSpeeds(ctx, &rev)
		if err != nil {
			t.Fatalf("watch failed: %v", err)
		}
		if elapsed := time.Since(started); elapsed >= time.Second {
			t.Fatalf("expected prompt expiry wake, took %v", elapsed)
		}
		if list.Revision <= rev || len(list.Tests) != 1 || list.Tests[0].Phase != "client-cleanup" || list.Tests[0].Error != "lease_expired_cleanup_unconfirmed" {
			t.Fatalf("unexpected expired speed list: %+v", list)
		}
	})

	t.Run("wakes-on-speed-fault", func(t *testing.T) {
		_, ca, key := identity(t, nil, nil, false)
		_, cert, _ := identity(t, ca, key, false)
		fingerprint := CertificateID(cert)
		s := store(t)
		s.speedWatchTimeout = 2 * time.Second
		if err := s.Put(Node{ID: "node-one", CertificateID: fingerprint, Desired: artifact(1)}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		rev := uint64(0)
		errCh := make(chan error, 1)
		go func() {
			_, err := s.WatchSpeeds(ctx, &rev)
			errCh <- err
		}()
		// Give the watcher a brief moment to enter select, then fault persistence.
		time.Sleep(25 * time.Millisecond)
		_ = os.Remove(s.speedStatePath())
		if err := os.Mkdir(s.speedStatePath(), 0700); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		_ = s.saveSpeedLocked()
		s.mu.Unlock()

		select {
		case err := <-errCh:
			if err == nil || err.Error() != "speed_state_unavailable" {
				t.Fatalf("expected speed_state_unavailable, got %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("WatchSpeeds did not wake on speed fault")
		}
	})
}
