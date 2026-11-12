//go:build linux

package control

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	pb "github.com/petauron/glivela/internal/controlpb"
	"google.golang.org/grpc"
)

func TestSpeedHeartbeatCPU(t *testing.T) {
	if os.Getenv("GLIVELA_SPEED_WAKE_BENCH") != "1" {
		t.Skip("explicit isolated CPU comparison only")
	}
	_, ca, signer := identity(t, nil, nil, false)
	server, _, _ := identity(t, ca, signer, true)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	s := store(t)
	app, err := NewServer("127.0.0.1:0", s, server, pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewUnstartedServer(app.Handler)
	listener.EnableHTTP2 = true
	listener.TLS = app.TLSConfig.Clone()
	listener.Config.HTTP2 = app.HTTP2
	listener.StartTLS()
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const nodes = 16
	certs := make([]string, nodes)
	clients := make([]*Client, 0, nodes)
	streams := make([]grpc.BidiStreamingClient[pb.NodeFrame, pb.ControllerFrame], 0, nodes)
	defer func() {
		cancel()
		for _, c := range clients {
			c.Close()
		}
	}()
	for i := range nodes {
		id, cert, _ := identity(t, ca, signer, false)
		certs[i] = CertificateID(cert)
		if err := s.Put(Node{ID: fmt.Sprintf("node-%02d", i), CertificateID: certs[i], Desired: artifact(1), ReportedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		c, err := NewClient(listener.URL, id, pool)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		streams = append(streams, openControl(t, ctx, c))
	}
	// Receive normally so transport lifecycle is real. No assignments or speed
	// traffic exist: this measures redundant idle control wakes from heartbeats.
	for _, stream := range streams {
		go func(stream grpc.BidiStreamingClient[pb.NodeFrame, pb.ControllerFrame]) {
			for {
				if _, err := stream.Recv(); err != nil {
					return
				}
			}
		}(stream)
	}
	time.Sleep(250 * time.Millisecond)
	cpu := func(who int) float64 {
		var v syscall.Rusage
		if err := syscall.Getrusage(who, &v); err != nil {
			t.Fatal(err)
		}
		return float64(v.Utime.Sec+v.Stime.Sec) + float64(v.Utime.Usec+v.Stime.Usec)/1e6
	}
	before, children := cpu(syscall.RUSAGE_SELF), cpu(syscall.RUSAGE_CHILDREN)
	start := time.Now()
	const rounds = 480
	for i := range rounds {
		s.mu.Lock()
		next := s.copy()
		n := next[certs[i%nodes]]
		n.ReportedAt = time.Now()
		next[certs[i%nodes]] = n
		err := s.commit(next)
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		// Each of 16 synthetic nodes reports every two seconds, same before/after.
		time.Sleep(time.Second * 2 / nodes)
	}
	elapsed := time.Since(start).Seconds()
	self, child := cpu(syscall.RUSAGE_SELF)-before, cpu(syscall.RUSAGE_CHILDREN)-children
	t.Logf("SPEED_WAKE_CPU nodes=%d rounds=%d interval_per_node=2s wall_s=%.3f self_s=%.6f children_s=%.6f cpu_percent=%.3f cpu_ms_per_commit=%.3f", nodes, rounds, elapsed, self, child, 100*(self+child)/elapsed, 1000*(self+child)/rounds)
}
