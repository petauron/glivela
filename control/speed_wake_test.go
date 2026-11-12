package control

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSpeedWakeScope(t *testing.T) {
	s := store(t)
	s.speedHub = newSpeedHub()
	certs := []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}
	for i, cert := range certs {
		s.nodes[cert] = Node{ID: []string{"entry-one", "landing-one", "unrelated-one"}[i], CertificateID: cert, Desired: artifact(1), ReportedAt: time.Now()}
		s.speedHub.nodes[cert] = &speedStreamSession{wake: make(chan struct{}, 1), cancel: func() {}}
	}
	drain := func(want ...int) {
		t.Helper()
		for i, cert := range certs {
			expected := false
			for _, v := range want {
				expected = expected || v == i
			}
			select {
			case <-s.speedHub.nodes[cert].wake:
				if !expected {
					t.Fatalf("unrelated session %d woken", i)
				}
			default:
				if expected {
					t.Fatalf("session %d not woken", i)
				}
			}
		}
	}
	commit := func(cert string, policy bool) {
		t.Helper()
		next := s.copy()
		node := next[cert]
		node.ReportedAt = time.Now()
		if policy {
			node.Desired = artifact(node.Desired.Revision + 1)
		}
		next[cert] = node
		if err := s.commit(next); err != nil {
			t.Fatal(err)
		}
	}
	commit(certs[0], false)
	drain()
	commit(certs[0], true)
	drain(0)
	s.speedJobs = map[string]*speedRecord{"test-job": {Target: latencyTarget{Certificate: certs[0]}, LandingCertificate: certs[1], Phase: "receiver"}}
	commit(certs[2], false)
	drain()
	commit(certs[0], false)
	drain(0, 1)
	if err := s.saveSpeedLocked(); err != nil {
		t.Fatal(err)
	}
	drain(0, 1)
	next := s.copy()
	delete(next, certs[0])
	if err := s.commit(next); err != nil {
		t.Fatal(err)
	}
	drain(0, 1)
	// A replaced session remains canceled, never retained by targeted notification.
	old := s.speedHub.nodes[certs[1]]
	canceled := false
	old.cancel = func() { canceled = true }
	s.speedHub.replace(certs[1], &speedStreamSession{wake: make(chan struct{}, 1), cancel: func() {}})
	if !canceled || s.speedHub.current(certs[1], old) {
		t.Fatal("replaced session retained")
	}
	if _, err := s.SpeedExchange(context.Background(), certs[1], nil, old); err == nil {
		t.Fatal("old session accepted")
	}
}
