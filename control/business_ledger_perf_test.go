package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	glivela "github.com/petauron/glivela"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Explicit local comparison only; standard CI never runs this workload. Both
// original and optimized binaries use this exact synthetic input and cadence.
func TestOwnedLedgerResourceComparison(t *testing.T) {
	if os.Getenv("GLIVELA_LEDGER_COMPARE") != "1" {
		t.Skip("explicit resource comparison only")
	}
	source, d, _, _ := subscriptionFixture(t, false)
	m := source.business.material
	m.Ownership = nil
	var archive map[string]any
	if err := json.Unmarshal(m.RetainedSource, &archive); err != nil {
		t.Fatal(err)
	}
	archive["historyPayloads"] = strings.Repeat("x", 15<<20)
	raw, err := json.Marshal(archive)
	if err != nil {
		t.Fatal(err)
	}
	m.RetainedSource = raw
	started := time.Now().UTC().Add(-time.Hour)
	m.Plan.Accounts = m.Plan.Accounts[:1]
	delete(m.SubscriptionTokens, "account-other")
	delete(m.ResetSchedules, "account-other")
	a := &m.Plan.Accounts[0]
	a.Account.Plan.TotalBytes = 0
	a.Account.Plan.ResetDays = 0
	m.Endpoints[0].ResetDay = 0
	m.Endpoints[0].TotalBytes = 0
	credential := a.Credentials[0]
	usage := a.Usage[0]
	counter := m.TrafficCounters[credential.ID]
	counter.StartedAt = started.Format(time.RFC3339Nano)
	counter.ObservedAt = started.Format(time.RFC3339Nano)
	a.Credentials = nil
	a.Usage = nil
	m.TrafficCounters = map[string]glivela.ImportTrafficCounters{}
	m.ProtocolSecrets = map[string]string{}
	for i := 0; i < 74; i++ {
		c := credential
		c.ID = fmt.Sprintf("credential-bench-%03d", i)
		if i == 0 {
			c.ID = "credential-example"
		}
		c.User = fmt.Sprintf("bench-%03d", i)
		secret := fmt.Sprintf("11111111-1111-4111-8111-%012d", i+1)
		c.Identity = glivela.Identity(secret)
		u := usage
		u.CredentialID = c.ID
		a.Credentials = append(a.Credentials, c)
		a.Usage = append(a.Usage, u)
		m.ProtocolSecrets[c.ID] = secret
		m.TrafficCounters[c.ID] = counter
	}
	entryPlan := *d.clone().Entry
	entryPlan.Credentials = nil
	for _, credential := range a.Credentials {
		entryPlan.Credentials = append(entryPlan.Credentials, glivela.CredentialMaterial{Credential: credential, ProtocolID: m.ProtocolSecrets[credential.ID]})
	}
	d, err = NewEntryDesired(entryPlan, *d.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	s, _, cert, _ := ownedSubscriptionFixture(t, m, d, false)
	samples := 30
	if v := os.Getenv("GLIVELA_LEDGER_SAMPLES"); v != "" {
		samples, err = strconv.Atoi(v)
		if err != nil || samples < 1 || samples > 120 {
			t.Fatal("invalid sample count")
		}
	}
	ioStat := func() map[string]int64 {
		if runtime.GOOS != "linux" {
			return map[string]int64{}
		}
		b, err := os.ReadFile("/proc/self/io")
		if err != nil {
			t.Fatal(err)
		}
		v := map[string]int64{}
		for _, line := range strings.Split(string(b), "\n") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				v[strings.TrimSuffix(parts[0], ":")], _ = strconv.ParseInt(parts[1], 10, 64)
			}
		}
		return v
	}
	runtime.GC()
	initial := s.business.material
	beforeIO := ioStat()
	var before, after syscall.Rusage
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for i := 1; i <= samples; i++ {
		<-ticker.C
		now := time.Now().UTC()
		receipt := quotaReceipt(s.nodes[cert].Desired, started, now, counter.RawUploadBytes+int64(i))
		receipt.Traffic.Counters = map[string]TrafficCounter{}
		for id := range m.TrafficCounters {
			receipt.Traffic.Counters[id] = TrafficCounter{Upload: counter.RawUploadBytes + int64(i), Download: counter.RawDownloadBytes + int64(2*i)}
		}
		if _, err = s.Exchange(context.Background(), cert, receipt); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(begin).Seconds()
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
		t.Fatal(err)
	}
	afterIO := ioStat()
	seconds := func(v syscall.Timeval) float64 { return float64(v.Sec) + float64(v.Usec)/1e6 }
	cpu := seconds(after.Utime) + seconds(after.Stime) - seconds(before.Utime) - seconds(before.Stime)
	live, err := os.Stat(filepath.Join(filepath.Dir(s.path), "business.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i, u := range s.business.material.Plan.Accounts[0].Usage {
		if u.Observed != initial.Plan.Accounts[0].Usage[i].Observed+int64(3*samples) {
			t.Fatal("traffic delta lost or duplicated")
		}
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(s.business.material)
	got, _ := json.Marshal(loaded.business.material)
	if !bytes.Equal(want, got) {
		t.Fatal("reopen changed identity, history or counters")
	}
	result := map[string]any{"samples": samples, "cadenceSeconds": 1, "counterRecords": 74, "archivePlaintextBytes": len(raw), "elapsedSeconds": elapsed, "cpuSeconds": cpu, "cpuPercentOneCore": cpu / elapsed * 100, "writeBytes": afterIO["write_bytes"] - beforeIO["write_bytes"], "logicalWriteBytes": afterIO["wchar"] - beforeIO["wchar"], "liveCheckpointBytes": live.Size(), "restartBusinessEqual": true, "diskMetricsAvailable": runtime.GOOS == "linux"}
	resultJSON, _ := json.Marshal(result)
	t.Log("RESOURCE_RESULT " + string(resultJSON))
}
