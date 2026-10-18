package control

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

func routedEntryArtifact(t *testing.T) Desired {
	t.Helper()
	return withRoutedEntry(t, entryArtifact(t, "entry-example", 1))
}

func withRoutedEntry(t *testing.T, d Desired) Desired {
	t.Helper()
	plan := *d.clone().Entry
	base := plan.Credentials[0]
	protocolID := uuid.NewString()
	route := glivela.Credential{ID: "route-example", AccountID: base.Credential.AccountID, Kind: glivela.RouteCredential, User: "route-user", Identity: glivela.Identity(protocolID), EntryID: base.Credential.EntryID, EgressID: "landing-example", Enabled: true}
	plan.Credentials = append(plan.Credentials, glivela.CredentialMaterial{Credential: route, ProtocolID: protocolID})
	plan.Grants = []glivela.RouteGrant{{ID: "grant-example", AccountID: route.AccountID, EntryID: route.EntryID, EgressID: route.EgressID, InboundTag: plan.RealityEndpoints[0].InboundTag, Base: base.Credential, Route: route, Mode: glivela.FixedMode, Enabled: true, DesiredRev: 1}}
	plan.Peers = []glivela.RoutePeer{{EgressID: route.EgressID, Address: "100.64.0.2", Port: 1080, ExitFamily: glivela.EgressIPv4Only}}
	network := d.EntryNetwork.clone()
	network.Source = &landing.PeerIdentity{ID: "entry-mesh", PublicKey: "nodekey:entry", Address: "100.64.0.3"}
	network.Peers = []EntryPeer{{EgressID: route.EgressID, Identity: landing.PeerIdentity{ID: "landing-mesh", PublicKey: "nodekey:landing", Address: "100.64.0.2"}, Target: "https://probe.example.test/exit", ExpectedExit: "8.8.8.8"}}
	d, err := NewEntryDesired(plan, network)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestEntryNetworkBindsCompleteRoutedPrivateIdentities(t *testing.T) {
	for _, fault := range []string{"none", "missing-network", "missing-source", "missing-peer", "extra-peer", "duplicate-peer", "wrong-address", "wrong-egress", "source-peer-id", "source-peer-key", "source-peer-address", "invalid-key", "invalid-id", "noncanonical-ip", "wrong-port", "private-exit", "wrong-exit-family", "plain-http", "target-userinfo", "target-query", "target-port", "target-size"} {
		t.Run(fault, func(t *testing.T) {
			d := routedEntryArtifact(t)
			n := d.EntryNetwork
			switch fault {
			case "missing-network":
				d.EntryNetwork = nil
			case "missing-source":
				n.Source = nil
			case "missing-peer":
				n.Peers = nil
			case "extra-peer":
				p := n.Peers[0]
				p.EgressID = "unused"
				n.Peers = append(n.Peers, p)
			case "duplicate-peer":
				n.Peers = append(n.Peers, n.Peers[0])
			case "wrong-address":
				n.Peers[0].Identity.Address = "100.64.0.9"
			case "wrong-egress":
				n.Peers[0].EgressID = "unrelated"
			case "source-peer-id":
				n.Peers[0].Identity.ID = n.Source.ID
			case "source-peer-key":
				n.Peers[0].Identity.PublicKey = n.Source.PublicKey
			case "source-peer-address":
				n.Source.Address = n.Peers[0].Identity.Address
			case "invalid-key":
				n.Peers[0].Identity.PublicKey = "key\n"
			case "invalid-id":
				n.Source.ID = strings.Repeat("a", 129)
			case "noncanonical-ip":
				n.Peers[0].Identity.Address = "::ffff:100.64.0.2"
			case "wrong-port":
				d.Entry.Peers[0].Port = 1081
			case "private-exit":
				n.Peers[0].ExpectedExit = "192.168.1.1"
			case "wrong-exit-family":
				n.Peers[0].ExpectedExit = "2001:4860:4860::8888"
			case "plain-http":
				n.Peers[0].Target = "http://probe.example.test/exit"
			case "target-userinfo":
				n.Peers[0].Target = "https://user:pass@probe.example.test/exit"
			case "target-query":
				n.Peers[0].Target += "?token=example"
			case "target-port":
				n.Peers[0].Target = "https://probe.example.test:0/exit"
			case "target-size":
				n.Peers[0].Target += "/" + strings.Repeat("a", 2048)
			}
			if (d.Validate() == nil) != (fault == "none") {
				t.Fatalf("accepted changed entry transport: %s", fault)
			}
		})
	}
	landingDesired := artifact(1)
	network := EntryNetwork{}
	landingDesired.EntryNetwork = &network
	if landingDesired.Validate() == nil {
		t.Fatal("landing accepted entry-only transport policy")
	}
}

func TestEntryNetworkCloneAndConstructionDoNotAliasCallerPolicy(t *testing.T) {
	d := routedEntryArtifact(t)
	n := d.EntryNetwork.clone()
	wanted, err := NewEntryDesired(*d.Entry, n)
	if err != nil {
		t.Fatal(err)
	}
	n.Peers[0].Identity.PublicKey = "nodekey:changed"
	n.Source.PublicKey = "nodekey:changed-source"
	if wanted.EntryNetwork.Peers[0].Identity.PublicKey == n.Peers[0].Identity.PublicKey || wanted.EntryNetwork.Source.PublicKey == n.Source.PublicKey {
		t.Fatal("constructor retained caller slice")
	}
	copy := d.clone()
	copy.EntryNetwork.Source.PublicKey = "nodekey:other-source"
	copy.EntryNetwork.Peers[0].ExpectedExit = "1.1.1.1"
	if d.EntryNetwork.Source.PublicKey == copy.EntryNetwork.Source.PublicKey || d.EntryNetwork.Peers[0].ExpectedExit == copy.EntryNetwork.Peers[0].ExpectedExit {
		t.Fatal("clone retained original network policy")
	}
}

func TestEntryTransportChangesRequireNewRevisionAndRemainUnverified(t *testing.T) {
	for _, field := range []string{"source", "peer", "target", "expected-exit"} {
		t.Run(field, func(t *testing.T) { checkEntryTransportRevision(t, field) })
	}
}

func checkEntryTransportRevision(t *testing.T, field string) {
	t.Helper()
	s := store(t)
	d := routedEntryArtifact(t)
	certificate := strings.Repeat("a", 64)
	if err := s.Put(Node{ID: "entry-example", CertificateID: certificate, Desired: d}); err != nil {
		t.Fatal(err)
	}
	changed := d.clone()
	switch field {
	case "source":
		changed.EntryNetwork.Source.PublicKey = "nodekey:new-source"
	case "peer":
		changed.EntryNetwork.Peers[0].Identity.PublicKey = "nodekey:new-peer"
	case "target":
		changed.EntryNetwork.Peers[0].Target = "https://other-probe.example.test/exit"
	case "expected-exit":
		changed.EntryNetwork.Peers[0].ExpectedExit = "1.1.1.1"
	}
	if changed.Validate() != nil || changed.ConfigSHA256 != d.ConfigSHA256 {
		t.Fatal("network-only change unexpectedly changed Xray bytes")
	}
	if s.Put(Node{ID: "entry-example", CertificateID: certificate, Desired: changed}) == nil {
		t.Fatal("network change reused revision and old receipt")
	}
	changed.Entry.Revision++
	changed, err := NewEntryDesired(*changed.Entry, *changed.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "entry-example", CertificateID: certificate, Desired: changed}); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loaded.Exchange(context.Background(), certificate, &glivela.AppliedReceipt{Revision: d.Revision, ConfigSHA256: d.ConfigSHA256, RuntimeReady: true})
	if err != nil || got.Revision != changed.Revision || got.EntryNetwork.Source.PublicKey != changed.EntryNetwork.Source.PublicKey || got.EntryNetwork.Peers[0] != changed.EntryNetwork.Peers[0] || loaded.nodes[certificate].Receipt != nil {
		t.Fatal("restart lost transport policy or accepted old runtime proof", err)
	}
}

func TestEntryNetworkRequiresBothExistingCompositePeers(t *testing.T) {
	d := routedEntryArtifact(t)
	plan := *d.clone().Entry
	plan.Grants[0].IPv4EgressID = "landing-v4"
	plan.Peers[0].ExitFamily = glivela.EgressIPv6Only
	plan.Peers[0].Ready = true
	plan.Peers = append(plan.Peers, glivela.RoutePeer{EgressID: "landing-v4", Address: "100.64.0.9", Port: 1080, ExitFamily: glivela.EgressIPv4Only, Ready: true})
	network := d.EntryNetwork.clone()
	network.Peers[0].ExpectedExit = "2001:4860:4860::8888"
	network.Peers = append(network.Peers, EntryPeer{EgressID: "landing-v4", Identity: landing.PeerIdentity{ID: "mesh-v4", PublicKey: "nodekey:v4", Address: "100.64.0.9"}, Target: "https://probe.example.test/exit", ExpectedExit: "1.1.1.1"})
	if _, err := NewEntryDesired(plan, network); err != nil {
		t.Fatal("complete existing composite policy rejected", err)
	}
	for _, fault := range []string{"missing-secondary", "duplicate-id", "duplicate-key", "duplicate-address"} {
		t.Run(fault, func(t *testing.T) {
			changed := network.clone()
			switch fault {
			case "missing-secondary":
				changed.Peers = changed.Peers[:1]
			case "duplicate-id":
				changed.Peers[1].Identity.ID = changed.Peers[0].Identity.ID
			case "duplicate-key":
				changed.Peers[1].Identity.PublicKey = changed.Peers[0].Identity.PublicKey
			case "duplicate-address":
				changed.Peers[1].Identity.Address = changed.Peers[0].Identity.Address
			}
			if _, err := NewEntryDesired(plan, changed); err == nil {
				t.Fatal("partial or ambiguous peer inventory accepted")
			}
		})
	}
}
