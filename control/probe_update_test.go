package control

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDrainedProbeUpdatePreservesAccountingAndRejectsStaleTail(t *testing.T) {
	s := store(t)
	q, d, started := quotaFixture(t)
	q.TotalBytes = 1000000
	cert := strings.Repeat("a", 64)
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: d, EntryQuota: q}); err != nil {
		t.Fatal(err)
	}
	receipt := quotaReceipt(d, started, time.Now().UTC().Add(-time.Second), 25)
	if _, err := s.Exchange(context.Background(), cert, receipt); err != nil {
		t.Fatal(err)
	}
	peer := d.EntryNetwork.Peers[0]
	request := ProbeUpdate{EntryID: "entry-example", Expected: TransportCheckpoint{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, Traffic: receipt.Traffic.clone()}, Targets: map[string]string{peer.EgressID: "https://probe.example.net"}}
	if s.UpdateProbeTargets(request) == nil {
		t.Fatal("unsealed worker accepted")
	}
	if err := s.RecordTransportTail(context.Background(), cert, TransportTail{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, Traffic: receipt.Traffic}); err != nil {
		t.Fatal(err)
	}
	before := s.nodes[cert]
	for _, target := range []string{"http://probe.example.net", "https://secret@probe.example.net", "https://probe.example.net/?token=secret", peer.Target} {
		bad := request
		bad.Targets = map[string]string{peer.EgressID: target}
		if s.UpdateProbeTargets(bad) == nil {
			t.Fatal("invalid/no-op target accepted")
		}
	}
	stale := before
	stale.TransportTail = &TransportTail{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, Traffic: receipt.Traffic.clone()}
	stale.TransportTail.Traffic.SampledAt = time.Now().UTC().Add(-61 * time.Second)
	stale.EntryQuota = before.EntryQuota.clone()
	stale.EntryQuota.Raw = stale.TransportTail.Traffic.clone()
	s.nodes[cert] = stale
	bad := request
	bad.Expected.Traffic = stale.TransportTail.Traffic.clone()
	if s.UpdateProbeTargets(bad) == nil {
		t.Fatal("expired tail accepted")
	}
	s.nodes[cert] = before
	if err := s.UpdateProbeTargets(request); err != nil {
		t.Fatal(err)
	}
	after := s.nodes[cert]
	if !probeOnlyEntryChange(d, after.Desired) || transportOnlyEntryChange(d, after.Desired) || after.Desired.Revision != d.Revision+1 {
		t.Fatal("change escaped probe scope")
	}
	ledger := after.EntryQuota.clone()
	ledger.Base, ledger.TransportOrigin = before.EntryQuota.Base, before.EntryQuota.TransportOrigin
	if !reflect.DeepEqual(ledger, before.EntryQuota) || !reflect.DeepEqual(*after.EntryQuota.TransportOrigin, before.EntryQuota.Base) {
		t.Fatal("ledger/origin changed")
	}
	if after.Receipt != nil || after.TransportTail != nil || !after.PublicationSuspended {
		t.Fatal("invented acceptance")
	}
	if s.UpdateProbeTargets(request) == nil {
		t.Fatal("replayed update accepted")
	}
	if _, err := OpenStore(s.path); err != nil {
		t.Fatal(err)
	}
	// Failed activation keeps the previous process accountable. Recovery is a
	// new revision with a fresh sample, never restoration of old ledger bytes.
	failedTail := quotaReceipt(d, started, time.Now().UTC(), 32)
	if err := s.RecordTransportTail(context.Background(), cert, TransportTail{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, Traffic: failedTail.Traffic}); err != nil {
		t.Fatal(err)
	}
	recover := ProbeUpdate{EntryID: request.EntryID, Expected: TransportCheckpoint{Revision: after.Desired.Revision, ConfigSHA256: after.Desired.ConfigSHA256, Traffic: failedTail.Traffic}, Targets: map[string]string{peer.EgressID: peer.Target}}
	if err := s.UpdateProbeTargets(recover); err != nil {
		t.Fatal(err)
	}
	restored := s.nodes[cert]
	if restored.EntryQuota.UsedBytes != before.EntryQuota.UsedBytes+7 || restored.Desired.Revision != d.Revision+2 || !reflect.DeepEqual(restored.Desired.EntryNetwork, d.EntryNetwork) {
		t.Fatal("recovery lost usage or policy")
	}
	if _, err := OpenStore(s.path); err != nil {
		t.Fatal(err)
	}
}
