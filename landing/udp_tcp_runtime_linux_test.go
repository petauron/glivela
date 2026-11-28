//go:build linux

package landing

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

// Actual SS2022/XUDP request-reply under the complete rendered landing and
// UID firewall. A fresh unrouted namespace contains every synthetic endpoint.
func TestRenderedLandingUDPOverTCP(t *testing.T) {
	if os.Getenv("GLIVELA_LANDING_UDP_TEST") != "1" {
		t.Skip("isolated Linux namespace required")
	}
	udpRuntimeNamespace(t, 0)
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fresh loopback-only namespace required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	core := os.Getenv("GLIVELA_XRAY_BINARY")
	version, err := exec.CommandContext(ctx, core, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(version), "Xray 26.11.9 ") {
		t.Fatal("packaged verified core required", err)
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatal(string(out), err)
		}
	}
	ip("link", "set", "lo", "up")
	for _, a := range []string{"100.64.0.10/32", "8.8.4.4/32", "9.9.9.9/32", "192.168.50.2/32", "192.168.50.3/32", "93.184.216.34/32"} {
		ip("addr", "add", a, "dev", "lo")
	}
	p := udpSSPlan()
	transport := p.Transport
	listenerPort := 1080
	sourceIP := "8.8.4.4"
	if os.Getenv("GLIVELA_UDP_LISTENER") == "shared" {
		p.Transport.Port = 24000
		p.Sources[0].UDPOverTCP = false
		p.ClientListeners = []ClientListener{{ID: "shared-example", Port: 24000, Key: p.Transport.Key, Source: sourceIP, Shared: true, Transport: glivela.IPv4ClientSS2022}}
		p.UDPOverTCPListeners = []string{"shared-example"}
		transport = p.Transport
		transport.ClientListenerID = "shared-example"
		listenerPort = 24000
	}
	if os.Getenv("GLIVELA_UDP_LISTENER") == "ipv6" {
		p.Sources[0].UDPOverTCP = false
		sourceIP = "2001:4860:4860::2222"
		address := "2001:4860:4860::8844"
		ip("-6", "addr", "add", sourceIP+"/128", "dev", "lo", "nodad")
		ip("-6", "addr", "add", address+"/128", "dev", "lo", "nodad")
		p.ClientListeners = []ClientListener{{ID: "ipv6-example", Port: 24001, Key: p.Transport.Key, Source: sourceIP, Transport: "ipv6-ss2022", Address: address}}
		p.UDPOverTCPListeners = []string{"ipv6-example"}
		transport = glivela.PrivateTransport{Protocol: "ss2022", Key: p.Transport.Key, PublicAddress: address, Port: 24001, ClientListenerID: "ipv6-example"}
		listenerPort = 24001
	}
	target := "93.184.216.34:8443"
	privateTarget := "192.168.50.3:8443"
	quicTarget := "93.184.216.34:443"
	if os.Getenv("GLIVELA_UDP_EGRESS_FAMILY") == "ipv6" {
		p.EgressIP = "2001:4860:4860::8888"
		ip("-6", "addr", "add", p.EgressIP+"/128", "dev", "lo", "nodad")
		ip("-6", "addr", "add", "2606:4700:4700::1111/128", "dev", "lo", "nodad")
		target = "[2606:4700:4700::1111]:8443"
		privateTarget = "[fd00::1]:8443"
		quicTarget = "[2606:4700:4700::1111]:443"
		ip("-6", "addr", "add", "fd00::1/128", "dev", "lo", "nodad")
	}
	peer, err := net.ListenPacket("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	sources := make(chan string, 32)
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := peer.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = peer.WriteTo(b[:n], a)
			host, _, _ := net.SplitHostPort(a.String())
			sources <- host
		}
	}()
	dir, err := os.MkdirTemp("", "glivela-udp-tcp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "xray")
	udpRuntimeCopyExecutable(t, core, binaryPath)
	start := func(name string, raw []byte, worker bool) *exec.Cmd {
		t.Helper()
		var diagnostic map[string]any
		if err := json.Unmarshal(raw, &diagnostic); err != nil {
			t.Fatal(err)
		}
		diagnostic["log"] = map[string]any{"loglevel": "debug"}
		raw, err = json.Marshal(diagnostic)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, name+".json")
		if err := os.WriteFile(file, raw, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, 0644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.CommandContext(ctx, binaryPath, "run", "-test", "-config", file).CombinedOutput(); err != nil {
			t.Fatal("real config test", err, string(out))
		}
		cmd := exec.CommandContext(ctx, binaryPath, "run", "-config", file)
		if worker {
			cmd.SysProcAttr = udpRuntimeCredential()
		}
		cmd.Env = append(os.Environ(), "GOMEMLIMIT=64MiB", "GOGC=50")
		logPath := filepath.Join(dir, name+".log")
		log, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			_ = log.Close()
			if t.Failed() {
				data, _ := os.ReadFile(logPath)
				if len(data) > 6000 {
					data = data[len(data)-6000:]
				}
				t.Log(name, string(data))
			}
		})
		return cmd
	}
	raw, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := p.Firewall(udpRuntimeWorkerUID, "lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = policy.Install(ctx); err != nil {
		t.Fatal(err)
	}
	if err = policy.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	start("landing", raw, true)
	outbounds := (glivela.RoutePeer{Transport: transport, Port: listenerPort}).ServerOutbounds("proxy", true)
	outbounds[0].(map[string]any)["sendThrough"] = sourceIP
	client := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"tag": "client", "listen": "127.0.0.1", "port": 19080, "protocol": "socks", "settings": map[string]any{"udp": true, "ip": "127.0.0.1"}}}, "outbounds": outbounds}
	encoded, _ := json.Marshal(client)
	start("client", encoded, false)
	var control net.Conn
	var relay string
	for deadline := time.Now().Add(4 * time.Second); ; {
		control, relay, err = udpRuntimeAssociate("127.0.0.1", "127.0.0.1:19080")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client unavailable", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	defer control.Close()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	packet := func(destination string, payload []byte) []byte {
		a, e := net.ResolveUDPAddr("udp", destination)
		if e != nil {
			t.Fatal(e)
		}
		b := []byte{0, 0, 0, 1}
		address := a.IP.To4()
		if address == nil {
			b[3] = 4
			address = a.IP.To16()
		}
		b = append(b, address...)
		b = binary.BigEndian.AppendUint16(b, uint16(a.Port))
		return append(b, payload...)
	}
	tcpTarget := strings.Replace(target, ":8443", ":8444", 1)
	tcpPeer, err := net.Listen("tcp", tcpTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpPeer.Close()
	go func() {
		for {
			c, e := tcpPeer.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				b := make([]byte, 128)
				n, e := c.Read(b)
				if e == nil {
					_, _ = c.Write(b[:n])
				}
			}()
		}
	}()
	tcpCheck := func() {
		t.Helper()
		c, e := net.DialTimeout("tcp4", "127.0.0.1:19080", time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = c.Write([]byte{5, 1, 0})
		method := make([]byte, 2)
		if _, e = io.ReadFull(c, method); e != nil || !bytes.Equal(method, []byte{5, 0}) {
			t.Fatal("TCP SOCKS greeting", e)
		}
		request := packet(tcpTarget, nil)
		request[0], request[1] = 5, 1
		_, _ = c.Write(request)
		header := make([]byte, 4)
		if _, e = io.ReadFull(c, header); e != nil || header[1] != 0 {
			t.Fatal("TCP SOCKS connect", e)
		}
		length := 6
		if header[3] == 4 {
			length = 18
		}
		if header[3] != 1 && header[3] != 4 {
			t.Fatal("unexpected TCP SOCKS reply")
		}
		if _, e = io.ReadFull(c, make([]byte, length)); e != nil {
			t.Fatal(e)
		}
		nonce := []byte(udpRuntimeNonce(t))
		_, _ = c.Write(nonce)
		got := make([]byte, len(nonce))
		if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, nonce) {
			t.Fatal("TCP echo regressed", e)
		}
	}
	tcpCheck()
	for _, size := range []int{64, 512, 1200} {
		for i := 0; i < 5; i++ {
			payload := []byte(udpRuntimeNonce(t))
			payload = append(payload, bytes.Repeat([]byte{'x'}, size-len(payload))...)
			got, err := udpRuntimeExchangeOn(u, relay, packet(target, payload))
			header := packet(target, nil)
			if err != nil || !bytes.Equal(got, append(header, payload...)) {
				t.Fatal("UDP-over-TCP request/reply failed", size, err)
			}
			select {
			case source := <-sources:
				if source != p.EgressIP {
					t.Fatal("UDP used another exit", source)
				}
			case <-time.After(time.Second):
				t.Fatal("UDP target observation missing")
			}
		}
	}
	for _, destination := range []string{privateTarget, quicTarget} {
		denied, err := net.ListenPacket("udp", destination)
		if err != nil {
			t.Fatal(err)
		}
		_ = denied.SetDeadline(time.Now().Add(600 * time.Millisecond))
		payload := []byte(udpRuntimeNonce(t))
		_, _ = u.WriteToUDP(packet(destination, payload), mustUDPAddress(t, relay))
		b := make([]byte, 2048)
		if n, _, err := denied.ReadFrom(b); err == nil && bytes.Contains(b[:n], payload) {
			denied.Close()
			t.Fatal("forbidden UDP target reached", destination)
		}
		denied.Close()
	}
	tcpCheck()
	// The server socket remains TCP-only even while encrypted UDP succeeds.
	ports, err := exec.CommandContext(ctx, "ss", "-H", "-lun").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ports), net.JoinHostPort(transport.PublicAddress, fmt.Sprint(listenerPort))) {
		t.Fatal("public UDP transport listener added")
	}
	t.Logf("verified %s SS2022 TCP-only with XUDP: 15/15 replies at 64/512/1200 bytes; private and UDP443 denied", p.EgressIP)
}

func mustUDPAddress(t *testing.T, value string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp4", value)
	if err != nil {
		t.Fatal(fmt.Errorf("relay: %w", err))
	}
	return a
}
