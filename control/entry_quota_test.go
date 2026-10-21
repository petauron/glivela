package control

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func TestEntryQuotaExchangePersistsPolicyAndCountersWithoutTouchingOtherNode(t *testing.T) {
	q, d, cutover := quotaFixture(t)
	q.ResetDay, q.Timezone, q.NextResetAt = 0, "", time.Time{}
	s := store(t)
	cert, otherCert := strings.Repeat("a", 64), strings.Repeat("b", 64)
	other := Node{ID: "untouched-entry", CertificateID: otherCert, Desired: entryArtifact(t, "untouched-entry", 1)}
	if err := s.Put(other); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: d, EntryQuota: q}); err != nil {
		t.Fatal(err)
	}
	before := s.nodes[otherCert]
	// A caller must not retain mutable ownership of the saved projection.
	q.UsedBytes = 0
	got, err := s.Exchange(context.Background(), cert, quotaReceipt(d, cutover, time.Now().UTC().Add(-time.Second), 25))
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != d.Revision+1 || s.nodes[cert].EntryQuota.UsedBytes != 105 {
		t.Fatal("exchange did not enforce quota")
	}
	if s.nodes[cert].Receipt != nil {
		t.Fatal("old receipt incorrectly proves new policy applied")
	}
	reopened, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.nodes[cert].EntryQuota.UsedBytes != 105 || reopened.nodes[cert].Desired.ConfigSHA256 != got.ConfigSHA256 {
		t.Fatal("policy/counter persistence diverged")
	}
	if !reflect.DeepEqual(before, s.nodes[otherCert]) {
		t.Fatal("another node changed")
	}
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: d}); err == nil {
		t.Fatal("ordinary enrollment removed quota")
	}
}

func quotaFixture(t *testing.T) (*EntryQuota, Desired, time.Time) {
	t.Helper()
	d := routedEntryArtifact(t)
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	q := &EntryQuota{TotalBytes: 100, UsedBytes: 80, ResetDay: 3, Timezone: "Asia/Singapore", NextResetAt: time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC), CutoverAt: now, Base: d.clone(), Forwarded: &EntryTraffic{StartedAt: now.Format(time.RFC3339Nano), SampledAt: now, Counters: map[string]TrafficCounter{}}}
	for _, c := range d.Entry.Credentials {
		q.Forwarded.Counters[c.Credential.ID] = TrafficCounter{}
	}
	return q, d, now
}

func quotaReceipt(d Desired, started, sampled time.Time, bytes int64) *Observation {
	counters := map[string]TrafficCounter{}
	for _, c := range d.Entry.Credentials {
		counters[c.Credential.ID] = TrafficCounter{}
	}
	counters[d.Entry.Credentials[0].Credential.ID] = TrafficCounter{Upload: bytes}
	return &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, RuntimeReady: true}, Traffic: &EntryTraffic{StartedAt: started.Format(time.RFC3339Nano), SampledAt: sampled, Counters: counters}}
}

func TestEntryQuotaExhaustionAndCalendarRecoveryPreserveCountersAndIdentity(t *testing.T) {
	q, d, now := quotaFixture(t)
	q1, disabled, err := advanceEntryQuota(q, d, quotaReceipt(d, now, now.Add(time.Second), 25), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if q.UsedBytes != 80 || q.Raw != nil || q1.UsedBytes != 105 || disabled.Revision != d.Revision+1 {
		t.Fatal("period changed incorrectly or input mutated")
	}
	for _, c := range disabled.Entry.Credentials {
		if c.Credential.Enabled {
			t.Fatal("over-quota native/route credential remained enabled")
		}
	}
	if disabled.ConfigSHA256 == d.ConfigSHA256 {
		t.Fatal("quota only changed metadata, not executable config")
	}
	if disabled.Validate() != nil {
		t.Fatal("disabled policy is not executable")
	}
	q2, recovered, err := advanceEntryQuota(q1, disabled, nil, q.NextResetAt)
	if err != nil {
		t.Fatal(err)
	}
	if q2.UsedBytes != 0 || q2.Forwarded.Counters[d.Entry.Credentials[0].Credential.ID].Upload != 25 {
		t.Fatal("cycle reset cleared lifetime transport counter")
	}
	expected := d.clone()
	expected.Entry.Revision = recovered.Revision
	if !reflect.DeepEqual(expected.Entry, recovered.Entry) || !reflect.DeepEqual(expected.EntryNetwork, recovered.EntryNetwork) {
		t.Fatal("recovery changed identity, credentials, routes or network policy")
	}
	if recovered.Revision != disabled.Revision+1 || !q2.LastResetAt.Equal(q.NextResetAt) {
		t.Fatal("cycle failed to restore policy")
	}
}

func TestEntryQuotaReplayRestartAndRefusedSamples(t *testing.T) {
	q, d, now := quotaFixture(t)
	sample := quotaReceipt(d, now, now.Add(time.Second), 5)
	q1, d1, err := advanceEntryQuota(q, d, sample, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	q2, _, err := advanceEntryQuota(q1, d1, sample, now.Add(2*time.Second))
	if err != nil || !reflect.DeepEqual(q1, q2) {
		t.Fatal("replay changed accounting", err)
	}
	q3, _, err := advanceEntryQuota(q2, d1, quotaReceipt(d1, now.Add(2*time.Second), now.Add(3*time.Second), 3), now.Add(3*time.Second))
	if err != nil || q3.UsedBytes != 88 {
		t.Fatal("restart lost or repeated bytes", err)
	}
	if _, _, err := advanceEntryQuota(q3, d1, quotaReceipt(d1, now.Add(2*time.Second), now.Add(4*time.Second), 2), now.Add(4*time.Second)); err == nil {
		t.Fatal("counter regression accepted")
	}
	bad := d.clone()
	bad.Entry.Credentials[0].ProtocolID = "changed"
	if _, _, err := advanceEntryQuota(q, bad, nil, now); err == nil {
		t.Fatal("changed identity accepted")
	}
}

func TestEntryQuotaResetCatchesUpAcrossOfflineDSTAndShortMonth(t *testing.T) {
	q, d, now := quotaFixture(t)
	zone, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	q.ResetDay, q.Timezone = 31, "America/New_York"
	q.NextResetAt = monthlyReset(2026, time.October, 31, zone)
	later := time.Date(2027, 3, 31, 0, 0, 0, 0, zone)
	got, _, err := advanceEntryQuota(q, d, nil, later)
	if err != nil {
		t.Fatal(err)
	}
	if got.UsedBytes != 0 || !got.LastResetAt.Equal(later) || !got.NextResetAt.Equal(time.Date(2027, 4, 30, 0, 0, 0, 0, zone)) || got.Forwarded.StartedAt != now.Format(time.RFC3339Nano) {
		t.Fatal("calendar reset drifted or cleared transport history")
	}
}
