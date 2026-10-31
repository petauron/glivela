package landing

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	glivela "github.com/petauron/glivela"
)

func TestIPv6ClientChainKeepsExistingLandingAndExactSource(t *testing.T) {
	p := fixturePlan()
	p.Sources = []Source{{Address: "100.64.0.11", PublicAddress: "1.1.1.1", TCPOnly: true}}
	p.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), PublicAddress: "9.9.9.9"}
	legacy := ClientListener{ID: "legacy", Port: 24000, Source: "1.1.1.1", Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	p.ClientListeners = []ClientListener{legacy}
	before, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	addition := ClientListener{ID: "new", Port: 24001, Source: "2001:4860:4860::8888", Address: "2606:4700:4700::1111", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), Transport: "ipv6-ss2022"}
	p.ClientListeners = append(p.ClientListeners, addition)
	after, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	var old, next struct {
		Inbounds  []map[string]any
		Outbounds []map[string]any
		Routing   struct{ Rules []map[string]any }
	}
	if json.Unmarshal(before, &old) != nil || json.Unmarshal(after, &next) != nil {
		t.Fatal("unreadable Xray config")
	}
	if len(old.Inbounds) != 2 || len(next.Inbounds) != 3 || !reflect.DeepEqual(old.Inbounds, next.Inbounds[:2]) || !reflect.DeepEqual(old.Outbounds, next.Outbounds) || !reflect.DeepEqual(old.Routing.Rules, next.Routing.Rules[:len(old.Routing.Rules)]) {
		t.Fatal("existing listener, source rules or egress changed")
	}
	client := next.Inbounds[2]
	settings, ok := client["settings"].(map[string]any)
	if !ok || client["listen"] != addition.Address || client["protocol"] != "shadowsocks" || settings["method"] != glivela.SS2022Method || settings["network"] != "tcp" {
		t.Fatal("wrong new listener")
	}
	lastRule := next.Routing.Rules[len(next.Routing.Rules)-1]
	if !reflect.DeepEqual(lastRule["source"], []any{addition.Source + "/128"}) || lastRule["network"] != "tcp" || lastRule["outboundTag"] != "egress" || next.Outbounds[0]["protocol"] != "blackhole" {
		t.Fatal("source or deny-by-default changed")
	}
	firewall, err := p.Firewall(990, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	var allowed, denied bool
	for _, object := range firewall.objects() {
		rule := object["rule"]
		if rule == nil || rule["chain"] != "input" {
			continue
		}
		b, _ := json.Marshal(rule["expr"])
		text := string(b)
		if strings.Contains(text, `"ip6"`) && strings.Contains(text, addition.Address) && strings.Contains(text, addition.Source) && strings.Contains(text, `"tcp"`) && strings.Contains(text, `"return"`) {
			allowed = true
		}
		if strings.Contains(text, `"ip6"`) && strings.Contains(text, addition.Address) && strings.Contains(text, `"drop"`) {
			denied = true
		}
	}
	if !allowed || !denied {
		t.Fatal("IPv6 listener lacks exact-source allow and deny rules")
	}
	for _, change := range []func(*ClientListener){
		func(c *ClientListener) { c.Source = "::/0" },
		func(c *ClientListener) { c.Source = "fd00::1" },
		func(c *ClientListener) { c.Address = "::" },
		func(c *ClientListener) { c.Port = legacy.Port },
	} {
		invalid := p
		invalid.ClientListeners = append([]ClientListener(nil), p.ClientListeners...)
		change(&invalid.ClientListeners[1])
		if invalid.Validate() == nil {
			t.Fatal("unscoped source, target or colliding port accepted")
		}
	}
}
