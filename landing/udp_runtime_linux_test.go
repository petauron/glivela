//go:build linux

package landing

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const udpRuntimeWorkerUID = 12345

// Opt-in packet acceptance for the complete landing plan and UID firewall,
// using the verified official 26.7.28 core provided by the native-package job.
// All addresses are local aliases in one fresh, unrouted network namespace.
// This exercises SOCKS5 UDP ASSOCIATE request/reply, NOT FullCone/NAT traversal,
// QUIC/Hysteria, unsolicited inbound packets, IPv6 UDP or UDP domain resolution.
func TestRenderedLandingUDP(t *testing.T) {
	if os.Getenv("GLIVELA_LANDING_UDP_TEST") != "1" {
		t.Skip("isolated Linux namespace required")
	}
	udpRuntimeNamespace(t, 0)
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("refusing UDP test outside a fresh loopback-only namespace", err)
	}
	binaryPath := os.Getenv("GLIVELA_XRAY_BINARY")
	if !filepath.IsAbs(binaryPath) {
		t.Fatal("verified official core path required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, binaryPath, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(version), "Xray 26.7.28 ") {
		t.Fatal("UDP acceptance requires the packaged Xray 26.7.28 core", err)
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated UDP interface: %s %v", out, err)
		}
	}
	ip("link", "set", "lo", "up")
	for _, address := range []string{"100.64.0.10/32", "100.64.0.11/32", "100.64.0.12/32", "100.64.0.13/32", "192.168.50.2/32", "192.168.50.3/32", "93.184.216.34/32"} {
		ip("addr", "add", address, "dev", "lo")
	}
	peers := map[string]*udpRuntimePeer{}
	for _, address := range []string{"93.184.216.34:8443", "192.168.50.3:8443", "93.184.216.34:22"} {
		peers[address] = newUDPRuntimePeer(t, address)
	}
	// Prove even the forbidden targets actually exist and answer outside the
	// dedicated worker policy. A missing fixture must not look like denial.
	for address := range peers {
		nonce := udpRuntimeNonce(t)
		got, err := udpRuntimeExchange("100.64.0.11", address, []byte(nonce))
		if err != nil || string(got) != "observed=100.64.0.11;"+nonce {
			t.Fatal("direct UDP control target unavailable", address, err)
		}
	}
	directory, err := os.MkdirTemp("", "glivela-isolated-udp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	core := filepath.Join(directory, "xray")
	udpRuntimeCopyExecutable(t, binaryPath, core)
	plan := Plan{Revision: 1, Address: "100.64.0.10", EgressIP: "192.168.50.2", Sources: []Source{
		{Address: "100.64.0.11"}, {Address: "100.64.0.12", TCPOnly: true},
	}}
	raw, err := plan.Render()
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(directory, "xray.json")
	if err := os.WriteFile(config, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := exec.CommandContext(ctx, core, "run", "-test", "-config", config).Run(); err != nil {
		t.Fatal("official core rejected the complete UDP landing plan", err)
	}
	policy, err := plan.Firewall(udpRuntimeWorkerUID, "lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Install(ctx); err != nil {
		t.Fatal(err)
	}
	if err := policy.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	worker := exec.CommandContext(ctx, core, "run", "-config", config)
	worker.SysProcAttr = udpRuntimeCredential()
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = worker.Process.Kill(); _ = worker.Wait() })
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", worker.Process.Pid))
	if err != nil || !strings.Contains(string(status), "\nUid:\t12345\t12345\t12345\t12345\n") {
		t.Fatal("Xray is not running under the dedicated non-root UID", err)
	}
	proxy := net.JoinHostPort(plan.Address, fmt.Sprint(SOCKSPort))
	var control net.Conn
	var relay string
	deadline := time.Now().Add(4 * time.Second)
	for {
		control, relay, err = udpRuntimeAssociate("100.64.0.11", proxy)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("authorized SOCKS UDP association unavailable", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer control.Close()
	validateRelay := func(address string) {
		t.Helper()
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != plan.Address || port == "0" || port == "" {
			t.Fatal("core returned a relay outside the assigned landing address", address, err)
		}
	}
	validateRelay(relay)
	t.Logf("SOCKS control=%s, association relay=%s", proxy, relay)
	allowed := func() {
		t.Helper()
		nonce := udpRuntimeNonce(t)
		got, err := udpRuntimeExchange("100.64.0.11", relay, udpRuntimePacket("93.184.216.34:8443", nonce))
		payload, parseErr := udpRuntimePayload(got, "93.184.216.34:8443")
		if err != nil || parseErr != nil || string(payload) != "observed=192.168.50.2;"+nonce {
			t.Fatal("authorized UDP failed or used another egress", err, parseErr,
				"target-observed sources:", peers["93.184.216.34:8443"].sources(nonce))
		}
		if observed := peers["93.184.216.34:8443"].sources(nonce); len(observed) != 1 || observed[0] != plan.EgressIP {
			t.Fatal("target did not independently observe the selected egress", observed)
		}
	}
	allowed()
	denied := map[string][]string{}
	assertDenied := func(source, destination, associationRelay string) {
		t.Helper()
		exchange := func(packet []byte) ([]byte, error) { return udpRuntimeExchange(source, associationRelay, packet) }
		if source == "100.64.0.11" {
			// Use one UDP source port for the allowed seed and forbidden next
			// destination, not merely the same TCP association with fresh flows.
			session, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(source)})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			exchange = func(packet []byte) ([]byte, error) { return udpRuntimeExchangeOn(session, associationRelay, packet) }
			seed := udpRuntimeNonce(t)
			got, err := exchange(udpRuntimePacket("93.184.216.34:8443", seed))
			payload, parseErr := udpRuntimePayload(got, "93.184.216.34:8443")
			if err != nil || parseErr != nil || string(payload) != "observed=192.168.50.2;"+seed {
				t.Fatal("allowed first datagram unavailable", err, parseErr)
			}
		}
		nonce := udpRuntimeNonce(t)
		_, err := exchange(udpRuntimePacket(destination, nonce))
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("expected bounded UDP denial, not a setup error or reply", err)
		}
		denied[destination] = append(denied[destination], nonce)
	}
	// Keep each TCP association alive. UDP is denied by source policy, not by
	// accidentally closing its control stream or disabling UDP globally.
	tcpOnlyControl, tcpOnlyRelay, err := udpRuntimeAssociate("100.64.0.12", proxy)
	if err != nil {
		t.Fatal("TCP-only source must still reach the SOCKS control listener", err)
	}
	defer tcpOnlyControl.Close()
	validateRelay(tcpOnlyRelay)
	// Test this source's own association. Sending to the other source's relay
	// would be rejected by Xray itself and would not exercise UDP authorization.
	assertDenied("100.64.0.12", "93.184.216.34:8443", tcpOnlyRelay)
	assertDenied("100.64.0.13", "93.184.216.34:8443", relay)
	unauthorized, _, err := udpRuntimeAssociate("100.64.0.13", proxy)
	if unauthorized != nil {
		unauthorized.Close()
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("unauthorized source reached TCP control or failed for an unrelated reason", err)
	}
	// Change destination after an allowed datagram: a first-packet decision
	// must not authorize private/management packets in an existing association.
	assertDenied("100.64.0.11", "192.168.50.3:8443", relay)
	assertDenied("100.64.0.11", "93.184.216.34:22", relay)
	allowed() // Denials must not be explained by a dead core/target.

	// Exercise the UID-scoped kernel guard independently of Xray routing.
	// Use this same test binary under the worker UID, never a shell or an
	// arbitrary command. The child permits only these fixed synthetic targets.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(directory, "udp-worker.test")
	udpRuntimeCopyExecutable(t, self, helper)
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"public", "private", "management"} {
		nonce := udpRuntimeNonce(t)
		command := exec.CommandContext(ctx, helper, "-test.run=^TestLandingUDPWorkerAttempt$", "-test.timeout=3s")
		command.Env = append(os.Environ(), "GLIVELA_UDP_WORKER_CASE="+scenario, "GLIVELA_UDP_WORKER_NONCE="+nonce, "GLIVELA_UDP_WORKER_NETNS="+namespace)
		command.SysProcAttr = udpRuntimeCredential()
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("dedicated-UID UDP control (%s): %s %v", scenario, out, err)
		}
		destination := udpRuntimeWorkerTarget(scenario)
		if scenario == "public" {
			if observed := peers[destination].sources(nonce); len(observed) != 1 || observed[0] != plan.EgressIP {
				t.Fatal("worker positive control did not reach target under its UID", observed)
			}
		} else {
			denied[destination] = append(denied[destination], nonce)
		}
	}
	// Negative proof is collected at the targets, not just from lost replies.
	for destination, nonces := range denied {
		for _, nonce := range nonces {
			if got := peers[destination].sources(nonce); len(got) != 0 {
				t.Fatal("forbidden UDP payload reached the controlled target", destination, got)
			}
		}
	}
	if err := policy.Verify(ctx); err != nil {
		t.Fatal("packet checks changed or lost the enforced policy", err)
	}
	// The namespace is destroyed by the CI caller. Never flush host rules.
	t.Log("verified literal IPv4 SOCKS UDP request/reply and source/UID denials; no FullCone or UDP-domain claim")
}

func udpRuntimeNamespace(t *testing.T, uid int) {
	t.Helper()
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || os.Geteuid() != uid {
		t.Fatal("refusing UDP fixture outside the isolated namespace/expected UID")
	}
	if uid == 0 {
		initial, err := os.Readlink("/proc/1/ns/net")
		if err != nil || current == initial {
			t.Fatal("refusing UDP fixture in the initial network namespace")
		}
	} else {
		// A non-root child cannot reliably inspect root-owned /proc/1/ns/net.
		// Bind it to the namespace already checked by its root parent instead.
		interfaces, err := net.Interfaces()
		if current != os.Getenv("GLIVELA_UDP_WORKER_NETNS") || err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
			t.Fatal("worker helper left its parent's loopback-only namespace")
		}
	}
}

func udpRuntimeCredential() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: udpRuntimeWorkerUID, Gid: udpRuntimeWorkerUID, Groups: []uint32{}}}
}

func udpRuntimeCopyExecutable(t *testing.T, source, target string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128<<20 {
		t.Fatal("unsafe fixture executable", err)
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.Chmod(0755); err != nil {
		output.Close()
		t.Fatal(err)
	}
	n, copyErr := io.Copy(output, io.LimitReader(input, (128<<20)+1))
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil || n != info.Size() {
		t.Fatal("fixture executable copy failed", copyErr, closeErr)
	}
}

func udpRuntimeNonce(t *testing.T) string {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(nonce[:])
}

type udpRuntimePeer struct {
	mu       sync.Mutex
	observed map[string][]string
}

func newUDPRuntimePeer(t *testing.T, address string) *udpRuntimePeer {
	t.Helper()
	endpoint, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.ListenUDP("udp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	peer := &udpRuntimePeer{observed: map[string][]string{}}
	done, failed := make(chan struct{}), make(chan error, 1)
	go func() {
		defer close(done)
		var buffer [512]byte
		for {
			n, source, err := connection.ReadFromUDP(buffer[:])
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					failed <- err
				}
				return
			}
			nonce := string(buffer[:n])
			peer.mu.Lock()
			if len(peer.observed) >= 64 || len(peer.observed[nonce]) >= 8 || n >= len(buffer) {
				peer.mu.Unlock()
				failed <- errors.New("UDP witness limit exceeded")
				return
			}
			peer.observed[nonce] = append(peer.observed[nonce], source.IP.String())
			peer.mu.Unlock()
			_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := connection.WriteToUDP([]byte("observed="+source.IP.String()+";"+nonce), source); err != nil {
				failed <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = connection.Close()
		<-done
		select {
		case err := <-failed:
			t.Error("controlled UDP witness failed", err)
		default:
		}
	})
	return peer
}

func (p *udpRuntimePeer) sources(nonce string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.observed[nonce]...)
}

func udpRuntimeExchange(source, target string, packet []byte) ([]byte, error) {
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(source)})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	return udpRuntimeExchangeOn(connection, target, packet)
}

func udpRuntimeExchangeOn(connection *net.UDPConn, target string, packet []byte) ([]byte, error) {
	endpoint, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return nil, err
	}
	_ = connection.SetDeadline(time.Now().Add(600 * time.Millisecond))
	if _, err := connection.WriteToUDP(packet, endpoint); err != nil {
		return nil, err
	}
	var response [1024]byte
	n, sender, err := connection.ReadFromUDP(response[:])
	if err != nil {
		return nil, err
	}
	if !sender.IP.Equal(endpoint.IP) || sender.Port != endpoint.Port || n == len(response) {
		return nil, errors.New("unexpected UDP responder or truncated packet")
	}
	return append([]byte(nil), response[:n]...), nil
}

func udpRuntimeAssociate(source, proxy string) (net.Conn, string, error) {
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}, Timeout: 600 * time.Millisecond}
	connection, err := dialer.Dial("tcp4", proxy)
	if err != nil {
		return nil, "", err
	}
	fail := func(err error) (net.Conn, string, error) { connection.Close(); return nil, "", err }
	_ = connection.SetDeadline(time.Now().Add(600 * time.Millisecond))
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(connection, method[:]); err != nil {
		return fail(err)
	}
	if method != [2]byte{5, 0} {
		return fail(errors.New("unexpected SOCKS authentication method"))
	}
	if _, err := connection.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(connection, reply[:]); err != nil {
		return fail(err)
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 || reply[3] != 1 {
		return fail(errors.New("UDP association was not accepted as IPv4"))
	}
	_ = connection.SetDeadline(time.Time{})
	return connection, net.JoinHostPort(net.IP(reply[4:8]).String(), fmt.Sprint(binary.BigEndian.Uint16(reply[8:10]))), nil
}

func udpRuntimePacket(target, nonce string) []byte {
	endpoint, err := net.ResolveUDPAddr("udp4", target)
	if err != nil || endpoint.IP.To4() == nil {
		panic("non-literal UDP fixture destination")
	}
	packet := []byte{0, 0, 0, 1}
	packet = append(packet, endpoint.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(endpoint.Port))
	return append(packet, nonce...)
}

func udpRuntimePayload(packet []byte, target string) ([]byte, error) {
	header := udpRuntimePacket(target, "")
	if len(packet) < len(header) || string(packet[:len(header)]) != string(header) {
		return nil, errors.New("wrong SOCKS UDP reply framing or target")
	}
	return packet[len(header):], nil
}

func udpRuntimeWorkerTarget(scenario string) string {
	switch scenario {
	case "public":
		return "93.184.216.34:8443"
	case "private":
		return "192.168.50.3:8443"
	case "management":
		return "93.184.216.34:22"
	}
	return ""
}

// A child-only helper in the same compiled test file: no scripts, shells,
// additional dependencies or arbitrary target arguments are needed.
func TestLandingUDPWorkerAttempt(t *testing.T) {
	scenario := os.Getenv("GLIVELA_UDP_WORKER_CASE")
	if scenario == "" {
		t.Skip("dedicated-UID UDP subprocess only")
	}
	udpRuntimeNamespace(t, udpRuntimeWorkerUID)
	nonce := os.Getenv("GLIVELA_UDP_WORKER_NONCE")
	decoded, err := hex.DecodeString(nonce)
	if err != nil || len(decoded) != 16 || udpRuntimeWorkerTarget(scenario) == "" {
		t.Fatal("invalid isolated UDP worker request")
	}
	got, err := udpRuntimeExchange("192.168.50.2", udpRuntimeWorkerTarget(scenario), []byte(nonce))
	if scenario == "public" {
		if err != nil || string(got) != "observed=192.168.50.2;"+nonce {
			t.Fatal("worker positive control unavailable", err)
		}
		return
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("kernel did not block direct worker UDP, or fixture failed", err)
	}
}
