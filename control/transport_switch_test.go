package control

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func TestPrivateTransportSwitchPreservesRetainedTraffic(t *testing.T) {
	s := store(t)
	q, d, started := quotaFixture(t)
	q.TotalBytes = 1000000
	entryCert, landingCert := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err := s.Put(Node{ID: "entry-example", CertificateID: entryCert, Desired: d, EntryQuota: q}); err != nil {
		t.Fatal(err)
	}
	land := Node{ID: "landing-example", CertificateID: landingCert, Desired: artifact(1)}
	if err := s.Put(land); err != nil {
		t.Fatal(err)
	}
	receipt := quotaReceipt(d, started, time.Now().UTC().Add(-time.Second), 25)
	if _, err := s.Exchange(context.Background(), entryCert, receipt); err != nil {
		t.Fatal(err)
	}
	before := s.nodes[entryCert].EntryQuota.clone()
	if err := s.RecordTransportTail(context.Background(), entryCert, TransportTail{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, Traffic: receipt.Traffic}); err != nil {
		t.Fatal(err)
	}
	request := TransportSwitch{LandingID: land.ID, Transport: glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw=="}, Expected: map[string]TransportCheckpoint{
		land.ID:         {Revision: 1, ConfigSHA256: land.Desired.ConfigSHA256},
		"entry-example": {Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, Traffic: receipt.Traffic.clone()},
	}}
	bad := request
	bad.Expected = map[string]TransportCheckpoint{land.ID: request.Expected[land.ID]}
	if s.SwitchPrivateTransport(bad) == nil {
		t.Fatal("partial pair accepted")
	}
	if err := s.SwitchPrivateTransport(request); err != nil {
		t.Fatal(err)
	}
	entry := s.nodes[entryCert]
	if entry.TransportPrevious == nil || !reflect.DeepEqual(*entry.TransportPrevious, d) || s.nodes[landingCert].TransportPrevious == nil || !reflect.DeepEqual(*s.nodes[landingCert].TransportPrevious, land.Desired) {
		t.Fatal("pre-switch execution configuration not retained")
	}
	after := entry.EntryQuota
	if after.TransportOrigin == nil || !reflect.DeepEqual(*after.TransportOrigin, before.Base) {
		t.Fatal("original accounting policy not retained")
	}
	if before.UsedBytes != after.UsedBytes || before.TotalBytes != after.TotalBytes || before.ResetDay != after.ResetDay || before.NextResetAt != after.NextResetAt || !reflect.DeepEqual(before.Raw, after.Raw) || !reflect.DeepEqual(before.Forwarded, after.Forwarded) {
		t.Fatal("retained ledger or cycle changed")
	}
	if !reflect.DeepEqual(d.Entry.Credentials, entry.Desired.Entry.Credentials) || !reflect.DeepEqual(d.EntryNetwork, entry.Desired.EntryNetwork) {
		t.Fatal("entry identity/network changed")
	}
	if entry.Receipt != nil || entry.Desired.Entry.Peers[0].Transport != request.Transport || s.nodes[landingCert].Desired.Landing.Transport != request.Transport {
		t.Fatal("pair not changed consistently")
	}
	if s.SwitchPrivateTransport(request) == nil {
		t.Fatal("replayed checkpoint accepted")
	}
	if _, err := OpenStore(s.path); err != nil {
		t.Fatal("stored switch cannot reload", err)
	}
	// New core counters append to the retained cumulative projection once.
	now := time.Now().UTC()
	newSample := quotaReceipt(entry.Desired, now.Add(-time.Millisecond), now, 7)
	q2, _, err := advanceEntryQuota(after, entry.Desired, newSample, now)
	if err != nil || q2.UsedBytes != after.UsedBytes+7 {
		t.Fatal("new core lost or duplicated traffic", err)
	}
	q3, _, err := advanceEntryQuota(q2, entry.Desired, newSample, now)
	if err != nil || q3.UsedBytes != q2.UsedBytes {
		t.Fatal("retry billed twice", err)
	}
	// Recovery changes only execution policy. New-generation usage remains
	// committed, and the old sample cannot authorize the reverse transaction.
	if err := s.RecordTransportTail(context.Background(), entryCert, TransportTail{Revision: entry.Desired.Revision, ConfigSHA256: entry.Desired.ConfigSHA256, Traffic: newSample.Traffic}); err != nil {
		t.Fatal(err)
	}
	currentLanding := s.nodes[landingCert]
	recovery := TransportSwitch{Recover: true, LandingID: land.ID, Transport: d.Entry.Peers[0].Transport, Expected: map[string]TransportCheckpoint{
		land.ID:         {Revision: currentLanding.Desired.Revision, ConfigSHA256: currentLanding.Desired.ConfigSHA256},
		"entry-example": {Revision: entry.Desired.Revision, ConfigSHA256: entry.Desired.ConfigSHA256, Traffic: newSample.Traffic.clone()},
	}}
	if err := s.SwitchPrivateTransport(recovery); err != nil {
		t.Fatal("configuration recovery refused", err)
	}
	recovered := s.nodes[entryCert]
	if !reflect.DeepEqual(recovered.EntryQuota.TransportOrigin, after.TransportOrigin) {
		t.Fatal("recovery changed accounting origin")
	}
	if recovered.EntryQuota.UsedBytes != q2.UsedBytes || !reflect.DeepEqual(recovered.EntryQuota.Forwarded, q2.Forwarded) || recovered.Desired.Revision <= entry.Desired.Revision || recovered.Desired.Entry.Peers[0].Transport != d.Entry.Peers[0].Transport || recovered.Receipt != nil {
		t.Fatal("recovery rolled back accounting or invented health")
	}
	if _, err := OpenStore(s.path); err != nil {
		t.Fatal("recovery cannot reload", err)
	}
}

func TestTransportTailRejectsExpiredSampleWithoutChangingLedger(t *testing.T) {
	s := store(t)
	q, d, started := quotaFixture(t)
	cert := strings.Repeat("a", 64)
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: d, EntryQuota: q}); err != nil {
		t.Fatal(err)
	}
	before := s.nodes[cert].EntryQuota.clone()
	receipt := quotaReceipt(d, started, time.Now().UTC().Add(-2*time.Minute), 25)
	if s.RecordTransportTail(context.Background(), cert, TransportTail{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, Traffic: receipt.Traffic}) == nil {
		t.Fatal("expired final sample accepted")
	}
	if !reflect.DeepEqual(s.nodes[cert].EntryQuota, before) || s.nodes[cert].TransportTail != nil {
		t.Fatal("rejected checkpoint changed accounting")
	}
}

func TestEncryptedProbeCannotFallBackToSOCKS(t *testing.T) {
	p := RouteProbe{Transport: glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw=="}}
	if _, err := CheckRoute(context.Background(), p); err == nil {
		t.Fatal("SS2022 silently used SOCKS")
	}
}

func TestUnlimitedTransportTailPreservesExistingCounterOrigin(t *testing.T) {
	s := store(t)
	d := routedEntryArtifact(t)
	cert := strings.Repeat("a", 64)
	ctx := context.Background()
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: d}); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	prior := quotaReceipt(d, started, time.Now().UTC().Add(-time.Second), 100)
	if _, err := s.Exchange(ctx, cert, prior); err != nil {
		t.Fatal(err)
	}
	tail := TransportTail{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, Traffic: quotaReceipt(d, started, time.Now().UTC(), 125).Traffic}
	if err := s.RecordTransportTail(ctx, cert, tail); err != nil {
		t.Fatal(err)
	}
	q := s.nodes[cert].EntryQuota
	credential := d.Entry.Credentials[0].Credential.ID
	if q.TotalBytes != 0 || q.ResetDay != 0 || q.UsedBytes != 25 || q.Forwarded.StartedAt != prior.Traffic.StartedAt || q.Forwarded.Counters[credential].Upload != 125 {
		t.Fatal("unlimited origin changed or bytes counted twice")
	}
	if err := s.RecordTransportTail(ctx, cert, tail); err != nil || s.nodes[cert].EntryQuota.UsedBytes != 25 {
		t.Fatal("tail retry changed usage", err)
	}
	if _, err := OpenStore(s.path); err != nil {
		t.Fatal("unlimited projection cannot reload", err)
	}
	// A restored process contributes only its new bytes, while the external
	// ledger still sees the original generation and cumulative counters.
	now := time.Now().UTC().Add(time.Second)
	next, _, err := advanceEntryQuota(q, d, quotaReceipt(d, now, now.Add(time.Second), 7), now.Add(time.Second))
	if err != nil || next.Forwarded.StartedAt != prior.Traffic.StartedAt || next.Forwarded.Counters[credential].Upload != 132 || next.UsedBytes != 32 {
		t.Fatal("restored unlimited worker lost or duplicated bytes", err)
	}
}

func TestFailedTransportActivationAccountsRetainedWorkerWithoutPublishingHealth(t *testing.T) {
	s := store(t)
	q, old, started := quotaFixture(t)
	q.TotalBytes = 1000000
	cert, landCert := strings.Repeat("a", 64), strings.Repeat("b", 64)
	land := artifact(1)
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: old, EntryQuota: q}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "landing-example", CertificateID: landCert, Desired: land}); err != nil {
		t.Fatal(err)
	}
	first := quotaReceipt(old, started, time.Now().UTC().Add(-time.Second), 25)
	if err := s.RecordTransportTail(context.Background(), cert, TransportTail{Revision: old.Revision, ConfigSHA256: old.ConfigSHA256, Traffic: first.Traffic}); err != nil {
		t.Fatal(err)
	}
	request := TransportSwitch{LandingID: "landing-example", Transport: glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw=="}, Expected: map[string]TransportCheckpoint{
		"entry-example":   {Revision: old.Revision, ConfigSHA256: old.ConfigSHA256, Traffic: first.Traffic},
		"landing-example": {Revision: land.Revision, ConfigSHA256: land.ConfigSHA256},
	}}
	if err := s.SwitchPrivateTransport(request); err != nil {
		t.Fatal(err)
	}
	current := s.nodes[cert].Desired
	last := quotaReceipt(old, started, time.Now().UTC(), 32)
	tail := TransportTail{Revision: old.Revision, ConfigSHA256: old.ConfigSHA256, Traffic: last.Traffic}
	if err := s.RecordTransportTail(context.Background(), cert, tail); err != nil {
		t.Fatal("retained worker final counters lost", err)
	}
	accounted := s.nodes[cert].EntryQuota.clone()
	if accounted.UsedBytes != q.UsedBytes+32 || s.nodes[cert].Receipt != nil {
		t.Fatal("recovery sample lost usage or published health")
	}
	if err := s.RecordTransportTail(context.Background(), cert, tail); err != nil || s.nodes[cert].EntryQuota.UsedBytes != q.UsedBytes+32 {
		t.Fatal("recovery retry changed ledger", err)
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	currentLand := loaded.nodes[landCert].Desired
	request.Expected = map[string]TransportCheckpoint{
		"entry-example":   {Revision: current.Revision, ConfigSHA256: current.ConfigSHA256, Traffic: last.Traffic},
		"landing-example": {Revision: currentLand.Revision, ConfigSHA256: currentLand.ConfigSHA256},
	}
	request.Transport = glivela.PrivateTransport{}
	if loaded.SwitchPrivateTransport(request) == nil {
		t.Fatal("previous runtime sample authorized a forward switch")
	}
	request.Recover = true
	if err := loaded.SwitchPrivateTransport(request); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(accounted.Forwarded, loaded.nodes[cert].EntryQuota.Forwarded) || loaded.nodes[cert].EntryQuota.UsedBytes != q.UsedBytes+32 {
		t.Fatal("recovery rewound ledger")
	}
}

func TestTransportTailIsDurableIdempotentAndNotHealth(t *testing.T) {
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
	tail := TransportTail{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, Traffic: receipt.Traffic.clone()}
	for id, counter := range tail.Traffic.Counters {
		counter.Upload += 5
		tail.Traffic.Counters[id] = counter
	}
	tail.Traffic.SampledAt = time.Now().UTC()
	if err := s.RecordTransportTail(context.Background(), cert, tail); err != nil {
		t.Fatal(err)
	}
	used := s.nodes[cert].EntryQuota.UsedBytes
	if used <= q.UsedBytes || s.nodes[cert].Receipt != nil || !s.nodes[cert].PublicationSuspended {
		t.Fatal("tail falsely published health or lost usage")
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.RecordTransportTail(context.Background(), cert, tail); err != nil {
		t.Fatal("lost response cannot retry", err)
	}
	if loaded.nodes[cert].EntryQuota.UsedBytes != used {
		t.Fatal("retry counted twice")
	}
	if _, err := loaded.Exchange(context.Background(), cert, receipt); err == nil {
		t.Fatal("normal polling bypassed maintenance checkpoint")
	}
	bad := tail
	bad.Traffic = tail.Traffic.clone()
	bad.Traffic.SampledAt = bad.Traffic.SampledAt.Add(time.Millisecond)
	if loaded.RecordTransportTail(context.Background(), cert, bad) == nil {
		t.Fatal("sealed sample replaced")
	}
	if loaded.ResumeTransportPreparation(context.Background(), cert, *receipt) == nil {
		t.Fatal("stale worker proof cancelled maintenance")
	}
	resumed := receipt.clone()
	resumed.Traffic = tail.Traffic.clone()
	resumed.Traffic.SampledAt = time.Now().UTC()
	if err := loaded.ResumeTransportPreparation(context.Background(), cert, resumed); err != nil {
		t.Fatal("verified original worker could not resume", err)
	}
	if loaded.nodes[cert].EntryQuota.UsedBytes != used || loaded.nodes[cert].TransportTail != nil || loaded.nodes[cert].Receipt != nil {
		t.Fatal("preparation recovery reset usage or invented health")
	}
}
