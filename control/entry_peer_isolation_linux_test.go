//go:build linux

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

func requireEntryPeerNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("GLIVELA_KERNEL_FIREWALL_TEST") != "1" {
		t.Skip("isolated Linux firewall namespace required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	initial, initialErr := os.Readlink("/proc/1/ns/net")
	if err != nil || initialErr != nil || current == initial || os.Geteuid() != 0 {
		t.Fatal("refusing test outside a separate root network namespace")
	}
}

func startupPeerLinks(desired Desired, wrongEntry bool, requests *int) func() *landing.LinkChecker {
	return func() *landing.LinkChecker {
		return &landing.LinkChecker{HTTPClient: &http.Client{Transport: startupStatusTransport(func(r *http.Request) (*http.Response, error) {
			*requests++
			var value any
			if r.URL.Path == "/localapi/v0/ping" {
				address := r.URL.Query().Get("ip")
				value = map[string]any{"IP": address, "NodeIP": address, "Endpoint": "203.0.113.8:41641"}
			} else {
				source := *desired.EntryNetwork.Source
				if wrongEntry {
					source.PublicKey = "nodekey:replacement"
				}
				peers := map[string]any{}
				for _, p := range desired.EntryNetwork.Peers {
					peers[p.EgressID] = map[string]any{"ID": p.Identity.ID, "PublicKey": p.Identity.PublicKey, "TailscaleIPs": []string{p.Identity.Address}, "Online": true}
				}
				value = map[string]any{"BackendState": "Running", "Self": map[string]any{"ID": source.ID, "PublicKey": source.PublicKey, "TailscaleIPs": []string{source.Address}}, "Peer": peers}
			}
			body, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
		})}}
	}
}

func cleanupStartupGates(t *testing.T, gates []*landing.TrafficGate) {
	t.Helper()
	t.Cleanup(func() {
		for _, gate := range gates {
			if gate.Verify(context.Background()) == nil {
				if err := gate.Block(context.Background()); err != nil {
					t.Error(err)
				}
			}
			if err := gate.Remove(context.Background()); err != nil {
				t.Error(err)
			}
		}
	})
}

// Real nftables policies in an isolated namespace; only the enrolled identity
// service and HTTPS observations are fixtures. No production route is used.
func TestEntryStartupPeerIsolation(t *testing.T) {
	requireEntryPeerNamespace(t)
	for _, mode := range []string{"one-blocked", "all-blocked", "entry-identity", "entry-process"} {
		t.Run(mode, func(t *testing.T) {
			desired := routedEntryArtifact(t)
			plan, network := *desired.Entry, desired.EntryNetwork.clone()
			plan.Peers = append(plan.Peers, glivela.RoutePeer{EgressID: "landing-second", Address: "100.64.0.4", Port: 1080, ExitFamily: glivela.EgressIPv4Only})
			network.Peers = append(network.Peers, EntryPeer{EgressID: "landing-second", Identity: landing.PeerIdentity{ID: "landing-second-mesh", PublicKey: "nodekey:second", Address: "100.64.0.4"}, Target: "https://probe.example.test/exit", ExpectedExit: "1.1.1.1"})
			var err error
			desired, err = NewEntryDesired(plan, network)
			if err != nil {
				t.Fatal(err)
			}
			var gates []*landing.TrafficGate
			for _, p := range network.Peers {
				gate, err := landing.NewHostGate(p.Identity, 12346, desired.Revision)
				if err != nil {
					t.Fatal(err)
				}
				gates = append(gates, gate)
			}
			cleanupStartupGates(t, gates)
			requests, probes := 0, 0
			ready := func(context.Context, Desired) error {
				if mode == "entry-process" {
					return errors.New("entry process unavailable")
				}
				return nil
			}
			monitors := &entryMonitors{}
			err = monitors.start(context.Background(), desired, gates, "entry-example", ready, startupPeerLinks(desired, mode == "entry-identity", &requests), func(_ context.Context, p RouteProbe) (RouteProbeResult, error) {
				probes++
				if p.LandingID == "landing-example" || mode == "all-blocked" {
					return RouteProbeResult{}, errors.New("landing unavailable")
				}
				return RouteProbeResult{Passed: true, ObservedExit: p.ExpectedExit}, nil
			})
			if mode == "entry-identity" || mode == "entry-process" {
				if err == nil || monitors.verify(desired) == nil {
					t.Fatal("entry identity/process failure was accepted")
				}
				return
			}
			if err != nil || probes != 2 || monitors.verify(desired) != nil {
				t.Fatalf("landing failure rejected entry or skipped another peer: %v, probes=%d", err, probes)
			}
			health := monitors.health(desired)
			if validateEntryHealth(desired, health) != nil || health.Peers["landing-example"].Status.State != "blocked" || gates[0].Verify(context.Background()) != nil {
				t.Fatal("failed peer lost its closed policy or truthful observation")
			}
			if mode == "one-blocked" && (health.Peers["landing-second"].Status.State != "healthy" || gates[1].Verify(context.Background()) == nil) {
				t.Fatal("healthy peer was blocked by a different landing")
			}
			if mode == "all-blocked" && (health.Peers["landing-second"].Status.State != "blocked" || gates[1].Verify(context.Background()) != nil) {
				t.Fatal("unavailable landing was falsely accepted")
			}
		})
	}
}

func TestEntryDriverDirectReadinessWithUnavailableLanding(t *testing.T) {
	requireEntryPeerNamespace(t)
	runtime, driver, worker, first := entryDriverFixture(t)
	desired := withRoutedEntry(t, first)
	requests, directChecks := 0, 0
	driver.links = startupPeerLinks(desired, false, &requests)
	driver.readinessProbe = func(context.Context, Desired) error { directChecks++; return nil }
	// There is no route to the synthetic landing in this fresh namespace, so
	// its actual SOCKS connect fails while the owned worker is a Docker fixture.
	if err := runtime.Apply(context.Background(), desired); err != nil {
		t.Fatal("failed landing prevented direct activation", err)
	}
	gates, err := driver.gates(desired)
	if err != nil {
		t.Fatal(err)
	}
	cleanupStartupGates(t, gates)
	health := driver.EntryHealth(desired)
	if worker.starts != 1 || worker.stops != 0 || directChecks != 1 || validateEntryHealth(desired, health) != nil || health.Peers["landing-example"].Status.State != "blocked" {
		t.Fatal("entry did not retain a ready worker and blocked landing")
	}
	previousRequests := requests
	if err := driver.Healthy(context.Background(), desired); err != nil || directChecks != 1 || requests != previousRequests || gates[0].Verify(context.Background()) != nil {
		t.Fatal("runtime health repeated startup probes or opened the failed landing", err)
	}
}
