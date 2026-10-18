package landing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEntryMonitorFreshEvidenceAndPeerScopedClosure(t *testing.T) {
	for _, mode := range []string{"healthy", "wrong-exit", "wrong-peer", "wrong-revision", "wrong-relay", "missing-udp", "tcp-only", "business-error", "relay-path"} {
		t.Run(mode, func(t *testing.T) {
			gate := fixtureGate(t)
			document := fixtureNFT(t, gate)
			writes, renewals := 0, 0
			gate.run = func(_ context.Context, input []byte, _ ...string) ([]byte, error) {
				if input == nil {
					return json.Marshal(document)
				}
				var transaction struct {
					Commands []map[string]map[string]nftObject `json:"nftables"`
				}
				if err := json.Unmarshal(input, &transaction); err != nil {
					t.Fatal(err)
				}
				writes++
				for _, command := range transaction.Commands {
					if command["flush"] != nil {
						delete(document.Objects[1]["set"], "elem")
					}
					if add := command["add"]; add != nil {
						// No rule/process lifecycle mutation is accepted during monitoring.
						element := add["element"]
						if element == nil || element["table"] != gate.table {
							t.Fatal("monitor changed another policy")
						}
						values := element["elem"].([]any)
						item := values[0].(map[string]any)["elem"].(map[string]any)
						item["expires"] = item["timeout"].(float64) - 0.1
						document.Objects[1]["set"]["elem"] = values
						renewals++
					}
				}
				return nil, nil
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/localapi/v0/ping" {
					ping := pingResult{IP: gate.peer.Address, NodeIP: gate.peer.Address, Endpoint: "203.0.113.8:41641"}
					if mode == "relay-path" {
						ping.DERPRegionID = 1
					}
					_ = json.NewEncoder(w).Encode(ping)
					return
				}
				_ = json.NewEncoder(w).Encode(localStatus{BackendState: "Running", Peer: map[string]*localPeer{"peer": {ID: gate.peer.ID, PublicKey: gate.peer.PublicKey, TailscaleIPs: []string{gate.peer.Address}}}})
			}))
			defer server.Close()
			checker := &LinkChecker{HTTPClient: &http.Client{Transport: latencyTransport{server.URL}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var status MonitorStatus
			monitor := Monitor{Gate: gate, Links: checker, ExpectedExit: "8.8.8.8", TCPOnly: mode == "tcp-only",
				CheckBusiness: func(_ context.Context, peer PeerIdentity, revision uint64) (BusinessResult, error) {
					if mode == "relay-path" {
						t.Fatal("business checked over unverified transport")
					}
					result := BusinessResult{Peer: peer, Revision: revision, TCP: true, UDP: true, UDPRelay: peer.Address + ":49152", ExitIP: "8.8.8.8", StartedAt: time.Now(), CheckedAt: time.Now()}
					switch mode {
					case "wrong-exit":
						result.ExitIP = "1.1.1.1"
					case "wrong-peer":
						result.Peer.PublicKey = "replacement"
					case "wrong-revision":
						result.Revision++
					case "wrong-relay":
						result.UDPRelay = "100.64.0.9:49152"
					case "missing-udp", "tcp-only":
						result.UDP = false
						result.UDPRelay = ""
					case "business-error":
						return result, errors.New("anonymous probe failure")
					}
					return result, nil
				}, Report: func(result MonitorStatus) { status = result; cancel() }}
			if err := monitor.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			wantHealthy := mode == "healthy" || mode == "tcp-only"
			if (status.State == "healthy") != wantHealthy || (renewals == 1) != wantHealthy || writes < 2 {
				t.Fatalf("state=%s renewals=%d writes=%d", status.State, renewals, writes)
			}
			if len(gate.elements(document)) != 0 {
				t.Fatal("monitor cancellation retained authorization")
			}
			if _, err := checker.SelfIdentity(context.Background(), "100.64.0.1"); err == nil {
				t.Fatal("monitor leaked its checker")
			}
		})
	}
}

func TestEntryLeaseRejectsStaleAndReorderedEvidence(t *testing.T) {
	gate := fixtureGate(t)
	now := time.Now()
	before := LinkResult{State: "direct", Reason: "fresh_disco_direct_response", StartedAt: now.Add(-time.Second), CheckedAt: now.Add(-900 * time.Millisecond)}
	business := BusinessResult{Peer: gate.peer, Revision: gate.revision, TCP: true, UDP: true, UDPRelay: gate.peer.Address + ":60000", ExitIP: "8.8.8.8", StartedAt: now.Add(-800 * time.Millisecond), CheckedAt: now.Add(-700 * time.Millisecond)}
	after := LinkResult{State: "direct", Reason: "fresh_disco_direct_response", StartedAt: now.Add(-600 * time.Millisecond), CheckedAt: now.Add(-500 * time.Millisecond)}
	if until, ok := leaseDeadlineForTransport(gate, before, business, after, now, false); !ok || !until.Equal(before.StartedAt.Add(AllowLifetime)) {
		t.Fatal("fresh evidence rejected or lifetime extended")
	}
	for _, mode := range []string{"old", "future", "business-before-link", "after-before-business", "no-tcp", "private-exit"} {
		a, b, c := before, business, after
		switch mode {
		case "old":
			a.StartedAt = now.Add(-AllowLifetime)
			a.CheckedAt = a.StartedAt
		case "future":
			c.CheckedAt = now.Add(time.Second)
		case "business-before-link":
			b.StartedAt = a.StartedAt
		case "after-before-business":
			c.StartedAt = b.StartedAt
		case "no-tcp":
			b.TCP = false
		case "private-exit":
			b.ExitIP = "192.168.1.1"
		}
		if _, ok := leaseDeadlineForTransport(gate, a, b, c, now, false); ok {
			t.Fatalf("accepted %s", mode)
		}
	}
}

func TestEntryMonitorRequiresExplicitPublicExit(t *testing.T) {
	for _, exit := range []string{"", "192.168.1.1", "::ffff:8.8.8.8"} {
		monitor := Monitor{Gate: fixtureGate(t), ExpectedExit: exit}
		if monitor.Run(context.Background()) == nil {
			t.Fatal("accepted incomplete monitor")
		}
	}
}
