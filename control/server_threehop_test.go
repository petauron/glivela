package control

import (
	"context"
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
	"reflect"
	"strings"
	"testing"
	"time"
)

// One path with an existing direct peer covers the isolation needed by migration.
func TestThreeHopServerPreservesDirectPeerAndIssuedListeners(t *testing.T) {
	s, entryCert, targetCert, grant := managedServerLandingFixture(t)
	revision := func() uint64 { return s.business.material.Plan.Accounts[0].Account.DesiredRevision }
	relayCert := strings.Repeat("c", 64)
	rp := *artifact(1).Landing
	rp.Address = "100.64.0.4"
	rp.EgressIP = "2001:4860:4860::1111"
	rp.Sources = nil
	rp.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: "MDEyMzQ1Njc4OWFiY2RlZg==", PublicAddress: "9.9.9.10"}
	rd, err := NewDesired(rp)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Put(Node{ID: "relay-example", CertificateID: relayCert, Desired: rd}); err != nil {
		t.Fatal(err)
	}
	exit := "8.8.8.8"
	change := ClientChainChange{ID: "three-hop", AccountID: grant.AccountID, EntryID: grant.EntryID, EgressID: grant.EgressID, Name: "Example via relay", Enabled: true, Transport: "ipv6-ss2022", SourceIPv6: rp.EgressIP, ServerIPv6: "2606:4700:4700::1111", RelayID: "relay-example", RelaySourceIPv6: "2001:4860:4860::8888", RelayServerIPv6: rp.EgressIP, EgressIP: &exit, ExpectedRevision: revision()}
	if _, err = s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal("create retained chain", err)
	}
	c, err := s.business.material.EffectiveClientChain(s.business.material.ClientChains[0])
	if err != nil {
		t.Fatal(err)
	}
	entry := s.nodes[entryCert]
	plan := *entry.Desired.clone().Entry
	network := entry.Desired.EntryNetwork.clone()
	direct := plan.Peers[0]
	path := direct
	path.ClientChainID = c.ID
	path.Relay = c.Relay
	path.Port = c.Port
	path.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: c.Key, PublicAddress: c.ServerIPv6, Port: c.Port, ClientListenerID: c.ID}
	plan.Peers = append(plan.Peers, path)
	plan.Revision++
	relayIdentity := landing.PeerIdentity{ID: "relay-mesh", PublicKey: "nodekey:relay", Address: rp.Address}
	npeer := network.Peers[0]
	npeer.ClientChainID = c.ID
	npeer.RelayIdentity = &relayIdentity
	network.Peers = append(network.Peers, npeer)
	entry.Desired, err = NewEntryDesired(plan, network)
	if err != nil {
		t.Fatal("independent path", err)
	}
	ownServerFixtureTransports(t, s, entry)
	if err = s.Put(entry); err != nil {
		t.Fatal("enroll path", err)
	}
	for cert, identity := range map[string]landing.PeerIdentity{relayCert: relayIdentity, targetCert: network.Peers[0].Identity} {
		n := s.nodes[cert]
		if _, err = s.Exchange(context.Background(), cert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: n.Desired.Revision, ConfigSHA256: n.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity}); err != nil {
			t.Fatal(err)
		}
	}
	entry = s.nodes[entryCert]
	target := s.nodes[targetCert]
	if _, ok := s.boundServerTransport(entry, target, path); !ok {
		t.Fatal("bound three-hop rejected")
	}
	request := landingAcceptanceRequest{SnapshotID: entry.ID, PeerID: c.ID, Revision: entry.Desired.Revision, ConfigSHA256: entry.Desired.ConfigSHA256}
	if proof, err := s.publicPeerAcceptance(entryCert, request); err != nil || proof.ClientChainID != c.ID || proof.LandingID != target.ID {
		t.Fatal("live three-node identity proof", err)
	}
	for _, fault := range []string{"key", "source", "certificate", "direction"} {
		bad := path
		r := *bad.Relay
		bad.Relay = &r
		switch fault {
		case "key":
			r.Key = "MDEyMzQ1Njc4OWFiY2RlZg=="
		case "source":
			r.SourceIPv6 = "2001:4860:4860::8844"
		case "certificate":
			r.CertificateID = targetCert
		case "direction":
			r.ServerIPv6 = c.ServerIPv6
		}
		if _, ok := s.boundServerTransport(entry, target, bad); ok {
			t.Fatal("accepted bad relay", fault)
		}
	}
	stale := s.nodes[relayCert]
	saved := stale
	stale.ReportedAt = time.Now().Add(-24 * time.Hour)
	s.nodes[relayCert] = stale
	if _, err = s.publicPeerAcceptance(entryCert, request); err == nil {
		t.Fatal("accepted stale relay")
	}
	s.nodes[relayCert] = saved
	grant.ClientChainID = c.ID
	grant.ExpectedRevision = revision()
	beforeRelay := s.nodes[relayCert].Desired
	beforeTarget := s.nodes[targetCert].Desired
	if _, err = s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal("grant three-hop", err)
	}
	check := func() {
		t.Helper()
		r := getSubscription(t, s, "/sub/example-token?format=mihomo", "Mihomo")
		if r.Code != 200 || !strings.Contains(r.Body.String(), c.Name) {
			t.Fatal("server subscription missing", r.Code)
		}
	}
	check()
	change.Enabled = false
	change.ExpectedRevision = revision()
	if _, err = s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal("withdraw old publication", err)
	}
	check()
	observation := healthyEntryObservation(s.nodes[entryCert].Desired, time.Now())
	for id, peer := range observation.EntryHealth.Peers {
		peer.Status.LinkState = "authenticated"
		observation.EntryHealth.Peers[id] = peer
	}
	if _, err = s.Exchange(context.Background(), entryCert, &observation); err != nil {
		t.Fatal("path health", err)
	}
	if !s.subscriptionPeerReady(s.nodes[entryCert], target.ID, time.Now(), c.ID) {
		t.Fatal("path-specific healthy receipt missing")
	}
	if r := getSubscription(t, s, "/sub/example-token?format=mihomo", "Mihomo"); strings.Contains(r.Body.String(), "dialer-proxy:") {
		t.Fatal("old client dependency retained in subscription")
	}
	if !reflect.DeepEqual(beforeRelay, s.nodes[relayCert].Desired) || !reflect.DeepEqual(beforeTarget, s.nodes[targetCert].Desired) {
		t.Fatal("withdrawing client changed listeners")
	}
	if !reflect.DeepEqual(direct, s.nodes[entryCert].Desired.Entry.Peers[0]) {
		t.Fatal("direct peer changed")
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err = json.Unmarshal(s.nodes[entryCert].Desired.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	relays := 0
	for _, o := range cfg.Outbounds {
		if _, ok := o["streamSettings"]; ok && o["protocol"] == "shadowsocks" {
			relays++
		}
	}
	if relays != 1 {
		t.Fatal("expected one server-side dialer", relays)
	}
}
