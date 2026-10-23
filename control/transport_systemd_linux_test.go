//go:build linux

package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

type installedTransportDiagnostic struct {
	*NativeEntryDriver
	t *testing.T
}

// The synthetic target rejects REALITY's fingerprint-discovery records. Close
// those rejected fixture connections completely, instead of leaving the core's
// discovery socket in CLOSE_WAIT indefinitely. The production drain check is
// deliberately unchanged: any remaining owned socket still aborts a cutover.
type transportTargetListener struct{ net.Listener }

func (l transportTargetListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
			_ = tcp.SetDeadline(time.Now().Add(2 * time.Second))
		}
	}
	return c, err
}

func (d *installedTransportDiagnostic) Activate(ctx context.Context, wanted Desired, previous *Desired) error {
	err := d.NativeEntryDriver.Activate(ctx, wanted, previous)
	if err != nil {
		d.t.Log("installed activation detail:", err, "process check:", d.readyProcess(ctx, wanted))
	}
	return err
}

// Opt-in acceptance in an authorized disposable systemd guest. The test and
// its dedicated worker share a NEW network namespace; no production enrollment
// or existing service is used. Real native driver, Xray, nft and journal I/O.
func TestInstalledTransportFailureRecovery(t *testing.T) {
	if os.Getenv("GLIVELA_SYSTEMD_TRANSPORT_TEST") != "1" {
		t.Skip("dedicated systemd guest required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	initial, initialErr := os.Readlink("/proc/1/ns/net")
	if err != nil || initialErr != nil || current == initial || os.Geteuid() != 0 {
		t.Fatal("separate root network namespace required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	command := func(name string, args ...string) {
		t.Helper()
		if err := exec.CommandContext(ctx, name, args...).Run(); err != nil {
			t.Fatalf("fixture %s failed: %v", name, err)
		}
	}
	command("/usr/sbin/ip", "link", "set", "lo", "up")
	for _, addr := range []string{"100.64.0.3/32", "93.184.216.34/32"} {
		command("/usr/sbin/ip", "addr", "add", addr, "dev", "lo")
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	target.Listener.Close()
	target.Listener, err = net.Listen("tcp", "93.184.216.34:443")
	if err != nil {
		t.Fatal(err)
	}
	target.Listener = transportTargetListener{target.Listener}
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	directory, err := os.MkdirTemp("/var/lib", "glivela-ss2022-acceptance-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	ca := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	t.Setenv("SSL_CERT_DIR", directory)
	const unit = "glivela-ss2022-acceptance.service"
	unitPath := "/etc/systemd/system/" + unit
	if _, err := os.Lstat(unitPath); !os.IsNotExist(err) {
		t.Fatal("refusing existing test unit")
	}
	binary := os.Getenv("GLIVELA_TEST_XRAY")
	bytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bytes)
	driver := &NativeEntryDriver{Directory: directory, SystemdDriver: SystemdDriver{Unit: unit, WorkerUser: "glivela-lab-xray", Role: "entry", Interface: "lo", Binary: binary, BinarySHA256: hex.EncodeToString(digest[:])}}
	driver.SystemdDriver, err = driver.ResolveWorker()
	if err != nil {
		t.Fatal(err)
	}
	unitData := fmt.Sprintf("[Unit]\nDescription=Isolated SS2022 recovery acceptance\n[Service]\nType=simple\nUser=%s\nGroup=%d\nNoNewPrivileges=yes\nRuntimeDirectory=glivela-ss2022-acceptance\nRuntimeDirectoryMode=0700\nNetworkNamespacePath=/proc/%d/ns/net\nExecStartPre=+/usr/bin/install -o %d -g %d -m 0600 %s/config.json /run/glivela-ss2022-acceptance/configuration\nExecStart=%s run -format json -config /run/glivela-ss2022-acceptance/configuration\nRestart=no\n", driver.WorkerUser, driver.WorkerGID, os.Getpid(), driver.WorkerUID, driver.WorkerGID, directory, binary)
	unitData += "CapabilityBoundingSet=\nAmbientCapabilities=\n"
	unitData += fmt.Sprintf("ExecStartPre=+/usr/bin/install -o %d -g %d -m 0600 %s /run/glivela-ss2022-acceptance/ca.pem\nEnvironment=SSL_CERT_FILE=/run/glivela-ss2022-acceptance/ca.pem\nEnvironment=SSL_CERT_DIR=/run/glivela-ss2022-acceptance\n", driver.WorkerUID, driver.WorkerGID, ca)
	if err := os.WriteFile(unitPath, []byte(unitData), 0644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = exec.Command("/usr/bin/systemctl", "stop", unit).Run()
		_ = exec.Command("/usr/bin/systemctl", "reset-failed", unit).Run()
		_ = os.Remove(unitPath)
		_ = exec.Command("/usr/bin/systemctl", "daemon-reload").Run()
	}()
	unitDigest := sha256.Sum256([]byte(unitData))
	driver.UnitSHA256 = hex.EncodeToString(unitDigest[:])
	command("/usr/bin/systemctl", "daemon-reload")
	q, old, _ := quotaFixture(t)
	plan := old.clone().Entry
	plan.RealityEndpoints[0].Target = "93.184.216.34:443"
	plan.RealityEndpoints[0].ServerNames = []string{"example.com"}
	old, err = NewEntryDesired(*plan, *old.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	q.TotalBytes = 1000000
	q.Base = old.clone()
	r := &NativeRuntime{Directory: directory, Driver: &installedTransportDiagnostic{NativeEntryDriver: driver, t: t}}
	defer driver.Close(context.Background())
	if err := r.Apply(ctx, old); err != nil {
		t.Fatal("initial installed worker", err)
	}
	r.Driver = driver
	s := store(t)
	cert := strings.Repeat("a", 64)
	landCert := strings.Repeat("b", 64)
	if err := s.Put(Node{ID: "entry-example", CertificateID: cert, Desired: old, EntryQuota: q}); err != nil {
		t.Fatal(err)
	}
	land := artifact(1)
	if err := s.Put(Node{ID: "landing-example", CertificateID: landCert, Desired: land}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client()}
	prepare := func() TransportTail {
		t.Helper()
		// Keep the live manager's health monitor group running during drainage.
		t.Log("preparing installed generation")
		tail, err := r.PrepareTransportTail(ctx)
		if err != nil {
			t.Fatal("actual drain", err)
		}
		if err = s.RecordTransportTail(ctx, cert, tail); err != nil {
			t.Fatal("tail acknowledgement", err)
		}
		if err = r.StopPreparedTransport(ctx); err != nil {
			t.Fatal("stop after ack", err)
		}
		t.Log("final sample acknowledged and worker stopped")
		return tail
	}
	switchPair := func(tail TransportTail, recover bool, transport glivela.PrivateTransport) {
		t.Helper()
		l := s.nodes[landCert].Desired
		e := s.nodes[cert].Desired
		if err := s.SwitchPrivateTransport(TransportSwitch{Recover: recover, LandingID: "landing-example", Transport: transport, Expected: map[string]TransportCheckpoint{"landing-example": {Revision: l.Revision, ConfigSHA256: l.ConfigSHA256}, "entry-example": {Revision: e.Revision, ConfigSHA256: e.ConfigSHA256, Traffic: tail.Traffic}}}); err != nil {
			t.Fatal("paired transaction", err)
		}
	}
	tail := prepare()
	switchPair(tail, false, glivela.PrivateTransport{Protocol: "ss2022", Key: "AAECAwQFBgcICQoLDA0ODw=="})
	candidate := s.nodes[cert].Desired
	injected := false
	r.writeJournal = func(dir, name string, raw []byte) error {
		var state runtimeJournal
		if json.Unmarshal(raw, &state) == nil && state.Phase == "ready" && state.Current != nil && state.Current.Revision == candidate.Revision && !injected {
			connection, dialErr := net.DialTimeout("tcp", "100.64.0.3:10443", 200*time.Millisecond)
			if dialErr == nil {
				connection.Close()
				t.Fatal("candidate accepted traffic before acknowledgement")
			}
			traffic, trafficErr := driver.traffic(ctx, candidate)
			if trafficErr != nil {
				t.Fatal("candidate counters unavailable", trafficErr)
			}
			for _, counter := range traffic.Counters {
				if counter.Upload != 0 || counter.Download != 0 {
					t.Fatal("fenced candidate accumulated unacknowledged user traffic")
				}
			}
			injected = true
			return errors.New("fixture failure after actual candidate activation")
		}
		return replacePrivate(dir, name, raw)
	}
	completionErr := r.CompleteTransport(ctx, client)
	t.Log("injected completion result", completionErr)
	if completionErr == nil || !injected {
		t.Fatal("candidate failure not exercised")
	}
	state, err := r.journal()
	if err != nil || state.Current == nil || state.Current.ConfigSHA256 != old.ConfigSHA256 {
		t.Fatal("original configuration not restored", err)
	}
	if err := driver.readyProcess(ctx, old); err != nil {
		t.Fatal("actual original worker not restored", err)
	}
	if err := driver.verifyTransportFence(ctx, old); err != nil {
		t.Fatal("failure lost fence", err)
	}
	conn, err := net.DialTimeout("tcp", "100.64.0.3:10443", 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("restored unacknowledged worker accepted traffic")
	}
	fresh := prepare()
	if fresh.Traffic.StartedAt == tail.Traffic.StartedAt {
		t.Fatal("restored process generation was not newly sampled")
	}
	switchPair(fresh, true, glivela.PrivateTransport{})
	r.writeJournal = nil
	if err := r.CompleteTransport(ctx, client); err != nil {
		t.Fatal("installed recovery completion", err)
	}
	if s.nodes[cert].EntryQuota.UsedBytes != q.UsedBytes {
		t.Fatal("fenced recovery changed retained usage")
	}
	conn, err = net.DialTimeout("tcp", "100.64.0.3:10443", time.Second)
	if err != nil {
		t.Fatal("acknowledged restored listener not reachable", err)
	}
	conn.Close()
	if _, err := os.Stat(filepath.Join(directory, "transport-prepared.json")); !os.IsNotExist(err) {
		t.Fatal("pending checkpoint retained after confirmed completion")
	}
	t.Log("real systemd candidate failed after activation; original worker restored fenced; fresh final tail recorded; reverse completion reopened listener without ledger rollback")
	// Probe-only maintenance uses exactly the same installed drain and final
	// accounting boundary, not live gate replacement or node re-enrollment.
	probeTail := prepare()
	beforeProbe := s.nodes[cert]
	peer := beforeProbe.Desired.EntryNetwork.Peers[0]
	if err := s.UpdateProbeTargets(ProbeUpdate{EntryID: beforeProbe.ID, Expected: TransportCheckpoint{Revision: beforeProbe.Desired.Revision, ConfigSHA256: beforeProbe.Desired.ConfigSHA256, Traffic: probeTail.Traffic}, Targets: map[string]string{peer.EgressID: "https://probe.example.net"}}); err != nil {
		t.Fatal("drained probe update", err)
	}
	if err := r.CompleteTransport(ctx, client); err != nil {
		t.Fatal("installed probe completion", err)
	}
	if s.nodes[cert].EntryQuota.UsedBytes != beforeProbe.EntryQuota.UsedBytes {
		t.Fatal("probe update changed retained usage")
	}
	conn, err = net.DialTimeout("tcp", "100.64.0.3:10443", time.Second)
	if err != nil {
		t.Fatal("probe update failed to reopen acknowledged listener", err)
	}
	conn.Close()
	t.Log("installed probe-only maintenance completed with retained accounting")
}
