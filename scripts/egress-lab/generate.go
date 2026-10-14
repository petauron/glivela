//go:build ignore

package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	m "github.com/petauron/glivela"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: generate.go ABSOLUTE_LAB_DIRECTORY")
	}
	directory := os.Args[1]
	if !filepath.IsAbs(directory) {
		panic("absolute lab directory required")
	}
	for _, policy := range []m.EgressPolicy{m.EgressAuto, m.EgressIPv4Only, m.EgressIPv6Only} {
		// Only the rendered production outbound is used in this focused core lab.
		// Full REALITY/HY2, Center/Agent and public-provider acceptance are separate.
		config, err := m.RenderXrayConfiguration(m.XrayPlan{
			Revision: 1, NativeEgress: policy,
			RealityEndpoints: []m.RealityEndpoint{{ID: "entry", EntryID: "entry", InboundTag: "entry",
				ListenAddress: "100.64.0.2", ListenPort: m.RealityBackendPort, AdvertiseHost: "entry.example.test", AdvertisePort: 443,
				Target: "target.example.test:443", ServerNames: []string{"target.example.test"}, PrivateKey: "fixture", PublicKey: "fixture", ShortIDs: []string{"0123456789abcdef"}}},
		})
		if err != nil {
			panic(err)
		}
		var rendered map[string]any
		if err := json.Unmarshal(config, &rendered); err != nil {
			panic(err)
		}
		fixture := map[string]any{
			"log": map[string]any{"loglevel": "warning"},
			"dns": map[string]any{"hosts": map[string]any{
				"dual.example.test": []string{"192.168.241.4", "fd00:397::4"},
				"v4.example.test":   "192.168.241.4",
				"v6.example.test":   "fd00:397::4",
			}, "servers": []string{"192.168.241.4"}},
			"inbounds": []any{map[string]any{"listen": "0.0.0.0", "port": 1080, "protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "192.168.241.2"}}},
			"outbounds": rendered["outbounds"],
		}
		data, err := json.Marshal(fixture)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(directory, string(policy)+".json"), data, 0644); err != nil {
			panic(err)
		}
	}
}
