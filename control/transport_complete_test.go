package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

type transportDriverFixture struct {
	*driverFixture
	removed bool
	started time.Time
}

func (d *transportDriverFixture) Activate(ctx context.Context, desired Desired, previous *Desired) error {
	if err := d.driverFixture.Activate(ctx, desired, previous); err != nil {
		return err
	}
	d.started = time.Now().UTC().Truncate(time.Second)
	return nil
}

func (d *transportDriverFixture) verifyTransportFence(context.Context, Desired) error {
	if d.removed {
		return errors.New("fixture fence missing")
	}
	return nil
}
func (d *transportDriverFixture) removeTransportFence(context.Context, Desired) error {
	d.removed = true
	return nil
}

func (d *transportDriverFixture) traffic(_ context.Context, desired Desired) (*EntryTraffic, error) {
	now := time.Now().UTC()
	return quotaReceipt(desired, d.started, now, 7).Traffic, nil
}

func TestExpiredPreparationCancellationPreservesLedger(t *testing.T) {
	r, base := nativeFixture(t)
	driver := &transportDriverFixture{driverFixture: base}
	r.Driver = driver
	q, old, started := quotaFixture(t)
	q.TotalBytes = 1000000
	ctx := context.Background()
	if err := r.Apply(ctx, old); err != nil {
		t.Fatal(err)
	}
	s := store(t)
	cert := strings.Repeat("a", 64)
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: old, EntryQuota: q}); err != nil {
		t.Fatal(err)
	}
	tail := TransportTail{Revision: old.Revision, ConfigSHA256: old.ConfigSHA256, Traffic: quotaReceipt(old, started, time.Now().UTC(), 25).Traffic}
	if err := s.RecordTransportTail(ctx, cert, tail); err != nil {
		t.Fatal(err)
	}
	// Advance the sealed fixture into an expired state without waiting a minute.
	tail.Traffic = tail.Traffic.clone()
	tail.Traffic.SampledAt = time.Now().UTC().Add(-2 * time.Minute)
	n := s.nodes[cert]
	n.TransportTail = &tail
	n.EntryQuota.Raw = tail.Traffic.clone()
	n.EntryQuota.Forwarded.SampledAt = tail.Traffic.SampledAt
	s.nodes[cert] = n
	saved := transportPreparation{Binding: driver.Binding(), Desired: old, Tail: tail}
	raw, _ := json.Marshal(saved)
	if err := replacePrivate(r.Directory, "transport-prepared.json", raw); err != nil {
		t.Fatal(err)
	}
	base.running = false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v1/transport-cancel-intent":
			var tail TransportTail
			if decode(req.Body, &tail) != nil {
				w.WriteHeader(400)
				return
			}
			desired, err := s.TransportCancelIntent(ctx, cert, tail)
			if err != nil {
				w.WriteHeader(409)
				return
			}
			_ = json.NewEncoder(w).Encode(desired)
		case "/v1/transport-resume":
			var actual Observation
			if decode(req.Body, &actual) != nil || s.ResumeTransportPreparation(ctx, cert, actual) != nil {
				w.WriteHeader(409)
				return
			}
			w.WriteHeader(503) // lost acknowledgement after commit
		default:
			var message exchange
			if decode(req.Body, &message) != nil {
				w.WriteHeader(400)
				return
			}
			desired, err := s.Exchange(ctx, cert, message.Receipt)
			if err != nil {
				w.WriteHeader(409)
				return
			}
			_ = json.NewEncoder(w).Encode(desired)
		}
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client()}
	if err := r.CancelTransport(ctx, client); err != nil {
		t.Fatal(err)
	}
	if s.nodes[cert].EntryQuota.UsedBytes != q.UsedBytes+25+7 || !driver.removed || !base.running {
		t.Fatal("cancellation lost accounting or did not restore original worker")
	}
}

func TestTransportCompletionRetainsCheckpointOnLostAcknowledgement(t *testing.T) {
	r, base := nativeFixture(t)
	r.Driver = &transportDriverFixture{driverFixture: base}
	_, old, started := quotaFixture(t)
	ctx := context.Background()
	if err := r.Apply(ctx, old); err != nil {
		t.Fatal(err)
	}
	tail := quotaReceipt(old, started, time.Now().UTC(), 25)
	saved := transportPreparation{Binding: r.Driver.Binding(), Desired: old, Tail: TransportTail{Revision: old.Revision, ConfigSHA256: old.ConfigSHA256, Traffic: tail.Traffic}}
	raw, _ := json.Marshal(saved)
	if err := replacePrivate(r.Directory, "transport-prepared.json", raw); err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	next.Entry.Revision++
	next.Entry.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw=="}
	desired, err := NewEntryDesired(*next.Entry, *next.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	failAck := true
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var message exchange
		if decode(req.Body, &message) != nil {
			w.WriteHeader(400)
			return
		}
		if message.Receipt != nil && failAck {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(desired)
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client()}
	if r.CompleteTransport(ctx, client) == nil {
		t.Fatal("lost acknowledgement reported success")
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "transport-prepared.json")); err != nil {
		t.Fatal("checkpoint lost", err)
	}
	starts := base.starts
	failAck = false
	if err := r.CompleteTransport(ctx, client); err != nil {
		t.Fatal(err)
	}
	if base.starts != starts {
		t.Fatal("retry restarted the accounted generation")
	}
	if _, err := os.Stat(filepath.Join(r.Directory, "transport-prepared.json")); !os.IsNotExist(err) {
		t.Fatal("completed checkpoint still pending", err)
	}
}

func TestTransportFailureRestoresConfigurationOnlyWhileFenced(t *testing.T) {
	for _, scenario := range []string{"failed-health", "expired-tail", "missing-fence"} {
		t.Run(scenario, func(t *testing.T) {
			r, base := nativeFixture(t)
			driver := &transportDriverFixture{driverFixture: base}
			r.Driver = driver
			_, old, started := quotaFixture(t)
			ctx := context.Background()
			if err := r.Apply(ctx, old); err != nil {
				t.Fatal(err)
			}
			sampled := time.Now().UTC()
			if scenario == "expired-tail" {
				sampled = sampled.Add(-2 * time.Minute)
			}
			tail := quotaReceipt(old, started, sampled, 25)
			saved := transportPreparation{Binding: driver.Binding(), Desired: old, Tail: TransportTail{Revision: old.Revision, ConfigSHA256: old.ConfigSHA256, Traffic: tail.Traffic}}
			raw, _ := json.Marshal(saved)
			if err := replacePrivate(r.Directory, "transport-prepared.json", raw); err != nil {
				t.Fatal(err)
			}
			next := old.clone()
			next.Entry.Revision++
			next.Entry.Peers[0].Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw=="}
			desired, err := NewEntryDesired(*next.Entry, *next.EntryNetwork)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(desired) }))
			defer server.Close()
			client := &Client{endpoint: server.URL, http: server.Client()}
			starts := base.starts
			if scenario == "failed-health" {
				base.failHealth = 1
			}
			if scenario == "missing-fence" {
				driver.removed = true
			}
			if r.CompleteTransport(ctx, client) == nil {
				t.Fatal("unsafe switch succeeded")
			}
			if scenario != "failed-health" && base.starts != starts {
				t.Fatal("aborted switch started worker")
			}
			if base.active.ConfigSHA256 != old.ConfigSHA256 {
				t.Fatal("old configuration not restored")
			}
			if scenario == "failed-health" && driver.removed {
				t.Fatal("failed activation released ingress")
			}
			if _, err := os.Stat(filepath.Join(r.Directory, "transport-prepared.json")); err != nil {
				t.Fatal("recovery checkpoint lost", err)
			}
		})
	}
}
