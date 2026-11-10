package landing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func clientOnlyFixture() Plan {
	p := fixturePlan()
	p.ClientOnly = true
	p.EgressIP = "9.9.9.9"
	p.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), PublicAddress: "9.9.9.9"}
	p.Sources = []Source{{Address: "100.64.0.11", PublicAddress: "1.1.1.1", TCPOnly: true}}
	p.ClientListeners = []ClientListener{
		{ID: "client-v4", Port: 24006, Source: "1.1.1.1", Transport: glivela.IPv4ClientSS2022, Key: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{ID: "client-v6", Port: 24007, Source: "2001:4860:4860::8888", Address: "2606:4700:4700::1111", Transport: "ipv6-ss2022", Key: base64.StdEncoding.EncodeToString(make([]byte, 16))},
	}
	return p
}

func TestClientOnlyLandingSeparatesTransportFromFinalIPv4(t *testing.T) {
	p := clientOnlyFixture()
	if _, err := p.RenderVersion(4); err == nil {
		t.Fatal("old runtime format accepted client-only policy")
	}
	raw, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Listen string
			Port   int
		}
		Outbounds []map[string]any
	}
	if json.Unmarshal(raw, &config) != nil || len(config.Inbounds) != 2 {
		t.Fatal("unexpected listeners")
	}
	for _, in := range config.Inbounds {
		if in.Port == SOCKSPort {
			t.Fatal("cohosted server transport was activated")
		}
	}
	if config.Inbounds[0].Listen != p.Transport.PublicAddress || config.Inbounds[1].Listen != p.ClientListeners[1].Address || config.Outbounds[1]["sendThrough"] != p.EgressIP {
		t.Fatal("transport changed final egress")
	}
	policy, err := p.Firewall(991, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if !policy.ClientOnly {
		t.Fatal("runtime and kernel policy differ")
	}
	objects, _ := json.Marshal(policy.objects())
	if bytes.Contains(objects, []byte(`"right":1080`)) || !bytes.Contains(objects, []byte(p.ClientListeners[1].Source)) {
		t.Fatal("unexpected base-port permission or missing exact source")
	}
	unsafe := p
	unsafe.Sources = append([]Source(nil), p.Sources...)
	unsafe.Sources[0].TCPOnly = false
	if unsafe.Validate() == nil {
		t.Fatal("client-only mode granted server UDP")
	}
	unsafe = p
	unsafe.ClientListeners = append([]ClientListener(nil), p.ClientListeners...)
	unsafe.ClientListeners[1].Source = "::/0"
	if unsafe.Validate() == nil {
		t.Fatal("wildcard client source accepted")
	}
	historical := p
	historical.ClientOnly = false
	old, err := historical.RenderVersion(4)
	if err != nil {
		t.Fatal(err)
	}
	current, err := historical.Render()
	if err != nil || !bytes.Equal(old, current) {
		t.Fatal("unchanged historical policy acquired different bytes")
	}
}

func TestOfficialClientOnlyLandingConfiguration(t *testing.T) {
	binary := os.Getenv("GLIVELA_XRAY_BINARY")
	if binary == "" {
		t.Skip("verified official Xray required")
	}
	p := clientOnlyFixture()
	raw, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client-only.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
		t.Fatalf("official Xray rejected client-only policy: %v %s", err, out)
	}
}
