//go:build linux

package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// Uses the existing opt-in installed worker fixture and synthetic HTTPS target.
// No production credentials, routes or external requests enter this comparison.
func compareNativeObservationCPU(t *testing.T, ctx context.Context, r *NativeRuntime) {
	t.Helper()
	cpu := func(who int) float64 {
		var v syscall.Rusage
		if err := syscall.Getrusage(who, &v); err != nil {
			t.Fatal(err)
		}
		return float64(v.Utime.Sec+v.Stime.Sec) + float64(v.Utime.Usec+v.Stime.Usec)/1e6
	}
	beforeSelf, beforeChildren := cpu(syscall.RUSAGE_SELF), cpu(syscall.RUSAGE_CHILDREN)
	started := time.Now()
	const rounds = 30
	for i := 0; i < rounds; i++ {
		sample, err := r.Inspect(ctx)
		if err != nil || !sample.RuntimeReady || sample.Traffic == nil {
			t.Fatalf("observation %d not accepted: ready=%v traffic=%v err=%v", i, sample.RuntimeReady, sample.Traffic != nil, err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	elapsed := time.Since(started).Seconds()
	usedSelf, usedChildren := cpu(syscall.RUSAGE_SELF)-beforeSelf, cpu(syscall.RUSAGE_CHILDREN)-beforeChildren
	t.Logf("OBSERVATION_CPU rounds=%d interval=2s wall_s=%.3f self_s=%.6f children_s=%.6f cpu_percent=%.3f cpu_ms_per_round=%.3f", rounds, elapsed, usedSelf, usedChildren, 100*(usedSelf+usedChildren)/elapsed, 1000*(usedSelf+usedChildren)/rounds)
	d := r.Driver.(*NativeEntryDriver)

	// Exercise a generation change after health acceptance but before counters.
	// This interface also lets the identical benchmark fixture compile on baseline.
	if sampler, ok := any(d).(interface {
		healthyProcess(context.Context, Desired) (nativeEntryProcess, error)
		trafficFromProcess(context.Context, Desired, nativeEntryProcess) (*EntryTraffic, error)
	}); ok {
		state, err := r.journal()
		if err != nil {
			t.Fatal(err)
		}
		before, err := sampler.healthyProcess(ctx, *state.Current)
		if err != nil {
			t.Fatal(err)
		}
		if err = exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", d.Unit).Run(); err != nil {
			t.Fatal(err)
		}
		sample, err := sampler.trafficFromProcess(ctx, *state.Current, before)
		if err == nil || sample != nil {
			t.Fatal("old process generation accepted after restart")
		}
		t.Log("Restart between health and accounting rejected without a sample")
	}
	// A later observation must recheck loaded identity, never reuse the prior round.
	path := "/etc/systemd/system/" + d.Unit
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(raw, []byte("\n# changed after accepted observation\n")...), 0644); err != nil {
		t.Fatal(err)
	}
	sample, err := r.Inspect(ctx)
	if err == nil && (sample.RuntimeReady || sample.Traffic != nil) {
		t.Fatal("changed owned unit was accepted")
	}
	if err = os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err = exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", d.Unit).Run(); err != nil {
		t.Fatal(err)
	}
	sample, err = r.Inspect(ctx)
	if err == nil && (sample.RuntimeReady || sample.Traffic != nil) {
		t.Fatal("stopped worker reused a healthy observation")
	}
}

// The current readiness probe authenticates a trace response, not HTTP 204.
// Keep DNS, TLS and the trace entirely inside the existing unrouted namespace.
// This uses the same fixture DNS approach as tools/alpine-acceptance.
func configureObservationTarget(t *testing.T, ctx context.Context, server *httptest.Server) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(108), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"example.com", "www.cloudflare.com"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	answer := func(raw []byte) []byte {
		var q dnsmessage.Message
		if q.Unpack(raw) != nil || q.Response || len(q.Questions) != 1 {
			return nil
		}
		a := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true}, Questions: q.Questions}
		query := q.Questions[0]
		if query.Name.String() != "www.cloudflare.com." && query.Name.String() != "example.com." {
			a.RCode = dnsmessage.RCodeNameError
		} else if query.Type == dnsmessage.TypeA {
			a.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}}}
		}
		b, _ := a.Pack()
		return b
	}
	for _, host := range []string{"1.1.1.1", "1.0.0.1"} {
		if err := exec.CommandContext(ctx, "ip", "addr", "add", host+"/32", "dev", "lo").Run(); err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenPacket("udp4", host+":53")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { udp.Close() })
		go func() {
			b := make([]byte, 4096)
			for {
				n, peer, e := udp.ReadFrom(b)
				if e != nil {
					return
				}
				if out := answer(b[:n]); out != nil {
					udp.WriteTo(out, peer)
				}
			}
		}()
		tcp, err := net.Listen("tcp4", host+":53")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tcp.Close() })
		go func() {
			for {
				c, e := tcp.Accept()
				if e != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					c.SetDeadline(time.Now().Add(5 * time.Second))
					for {
						var size [2]byte
						if _, e := io.ReadFull(c, size[:]); e != nil {
							return
						}
						b := make([]byte, int(binary.BigEndian.Uint16(size[:])))
						if _, e := io.ReadFull(c, b); e != nil {
							return
						}
						out := answer(b)
						if out == nil {
							return
						}
						binary.BigEndian.PutUint16(size[:], uint16(len(out)))
						if _, e := c.Write(append(size[:], out...)); e != nil {
							return
						}
					}
				}(c)
			}
		}()
	}
}
