package glivela

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestUDPServerRouteAndSubscriptions(t *testing.T) {
	p := compositePlanFixture()
	for i := range p.Peers {
		p.Peers[i].Transport = PrivateTransport{Protocol: "ss2022", Key: "MDEyMzQ1Njc4OWFiY2RlZg=="}
	}
	beforeVersion := uint8(31) | 64
	before, err := renderXrayConfiguration(p, beforeVersion)
	if err != nil {
		t.Fatal(err)
	}
	current, err := RenderXrayConfiguration(p)
	if err != nil || string(before) != string(current) {
		t.Fatal("default format changed", err)
	}
	p.Grants[0].UDP = true
	if _, err := renderXrayConfiguration(p, 31); err == nil {
		t.Fatal("old node accepted new capability")
	}
	raw, err := RenderXrayConfiguration(p)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Outbounds []struct {
			Mux struct {
				Enabled         bool
				Concurrency     int
				XudpConcurrency int
				XudpProxyUDP443 string
			}
		}
		Routing struct{ Rules []map[string]any }
	}
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("invalid configuration")
	}
	n := 0
	for _, o := range config.Outbounds {
		if o.Mux.Enabled {
			n++
			if o.Mux.Concurrency != -1 || o.Mux.XudpConcurrency != 1 || o.Mux.XudpProxyUDP443 != "reject" {
				t.Fatal("TCP multiplexing or QUIC policy changed")
			}
		}
	}
	if n != 2 || !strings.Contains(string(raw), `"network":"udp","outboundTag":"blocked","port":"443"`) {
		t.Fatal("missing family capability or UDP443 guard")
	}
	p.Peers[0].Transport = PrivateTransport{}
	if _, err := RenderXrayConfiguration(p); err == nil {
		t.Fatal("SOCKS transport accepted UDP-over-TCP")
	}

	grant := p.Grants[0]
	grant.IPv4EgressID = ""
	endpoint := p.RealityEndpoints[0]
	base, err := LinkForCredential(endpoint, p.Credentials[0], "Example")
	if err != nil {
		t.Fatal(err)
	}
	routed, err := LinkForCredential(endpoint, p.Credentials[1], "Example route")
	if err != nil {
		t.Fatal(err)
	}
	entries := []NativeEntry{{Material: p.Credentials[0], Protocol: VLESSReality, Link: base}}
	for _, applied := range []bool{false, true} {
		pub := PublishedRoute{UDP: applied, Grant: grant, Protocol: VLESSReality, EntryName: "Example", BaseLink: base, RouteLink: routed, BaseProtocolIdentity: grant.Base.Identity, RouteProtocolIdentity: grant.Route.Identity}
		links, err := RenderLinks(entries, "account", FixedMode, []PublishedRoute{pub}, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		flag := "udp=0"
		if applied {
			flag = "udp=1"
		}
		if !strings.Contains(string(links), flag) {
			t.Fatal("URI capability differs from application")
		}
		body, _, err := RenderMihomo(entries, "account", FixedMode, []PublishedRoute{pub}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var feed struct {
			Proxies []struct {
				UUID string
				UDP  bool
			}
		}
		if yaml.Unmarshal(body, &feed) != nil {
			t.Fatal("invalid feed")
		}
		found := false
		for _, proxy := range feed.Proxies {
			if proxy.UUID == p.Credentials[1].ProtocolID {
				found = true
				if proxy.UDP != applied {
					t.Fatal("Mihomo capability differs")
				}
			}
		}
		if !found {
			t.Fatal("pending route disappeared")
		}
		shadow, err := RenderShadowrocketNodes(body)
		if err != nil || !strings.Contains(string(shadow), flag) {
			t.Fatal("Shadowrocket capability differs", err, string(shadow))
		}
	}
}
