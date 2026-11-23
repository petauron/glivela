package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// One path with an existing direct peer covers the isolation needed by three-hop routes.
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
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	relayKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 16))
	chainID, port, serverIPv6, exit := "three-hop", 24001, "2606:4700:4700::1111", "8.8.8.8"
	relay := &glivela.ClientChainRelay{
		NodeID:        "relay-example",
		CertificateID: relayCert,
		Port:          port,
		Key:           relayKey,
		SourceIPv6:    "2001:4860:4860::8888",
		ServerIPv6:    rp.EgressIP,
	}
	entry := s.nodes[entryCert]
	plan := *entry.Desired.clone().Entry
	network := entry.Desired.EntryNetwork.clone()
	direct := plan.Peers[0]
	path := direct
	path.ClientChainID = chainID
	path.Relay = relay
	path.Port = port
	path.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: key, PublicAddress: serverIPv6, Port: port, ClientListenerID: chainID}
	plan.Peers = append(plan.Peers, path)
	plan.Revision++
	relayIdentity := landing.PeerIdentity{ID: "relay-mesh", PublicKey: "nodekey:relay", Address: rp.Address}
	npeer := network.Peers[0]
	npeer.ClientChainID = chainID
	npeer.RelayIdentity = &relayIdentity
	network.Peers = append(network.Peers, npeer)
	entry.Desired, err = NewEntryDesired(plan, network)
	if err != nil {
		t.Fatal("independent path", err)
	}
	relayListener := glivela.TransportListener{ID: chainID, Port: port, Key: relayKey, Source: relay.SourceIPv6, Transport: "ipv6-ss2022", Address: relay.ServerIPv6}
	resource := glivela.ServerTransport{
		ID:                   chainID,
		Name:                 "Example via relay",
		AccountID:            grant.AccountID,
		EntryID:              grant.EntryID,
		EgressID:             grant.EgressID,
		EntryCertificateID:   entryCert,
		LandingCertificateID: targetCert,
		Peer:                 path,
		ExpectedExit:         npeer.ExpectedExit,
		Listener:             glivela.TransportListener{ID: chainID, Port: port, Key: key, Source: rp.EgressIP, Transport: "ipv6-ss2022", Address: serverIPv6, EgressIP: exit},
		RelayListener:        &relayListener,
	}
	enrollFixtureServerTransport(t, s, entry, resource)
	reportLandings := func() {
		t.Helper()
		for cert, identity := range map[string]landing.PeerIdentity{relayCert: relayIdentity, targetCert: network.Peers[0].Identity} {
			n := s.nodes[cert]
			if _, err = s.Exchange(context.Background(), cert, &Observation{AppliedReceipt: glivela.AppliedReceipt{Revision: n.Desired.Revision, ConfigSHA256: n.Desired.ConfigSHA256, RuntimeReady: true}, ManagementIdentity: &identity}); err != nil {
				t.Fatal(err)
			}
		}
	}
	reportLandings()
	grant.ClientChainID = chainID
	grant.ExpectedRevision = revision()
	if _, err = s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal("grant three-hop", err)
	}
	reportLandings()
	entry = s.nodes[entryCert]
	target := s.nodes[targetCert]
	beforeRelay := s.nodes[relayCert].Desired
	beforeTarget := s.nodes[targetCert].Desired
	if _, ok := s.boundServerTransport(entry, target, path); !ok {
		t.Fatal("bound three-hop rejected")
	}
	request := landingAcceptanceRequest{SnapshotID: entry.ID, PeerID: chainID, Revision: entry.Desired.Revision, ConfigSHA256: entry.Desired.ConfigSHA256}
	if proof, err := s.publicPeerAcceptance(entryCert, request); err != nil || proof.ClientChainID != chainID || proof.LandingID != target.ID {
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
			r.ServerIPv6 = serverIPv6
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
	r := getSubscription(t, s, "/sub/example-token?format=mihomo", "Mihomo")
	if r.Code != 200 || !strings.Contains(r.Body.String(), resource.Name) || strings.Contains(r.Body.String(), "dialer-proxy:") {
		t.Fatal("server subscription missing or contained dialer-proxy", r.Code)
	}
	observation := healthyEntryObservation(s.nodes[entryCert].Desired, time.Now())
	for id, peer := range observation.EntryHealth.Peers {
		peer.Status.LinkState = "authenticated"
		observation.EntryHealth.Peers[id] = peer
	}
	if _, err = s.Exchange(context.Background(), entryCert, &observation); err != nil {
		t.Fatal("path health", err)
	}
	if !s.subscriptionPeerReady(s.nodes[entryCert], target.ID, time.Now(), chainID) {
		t.Fatal("path-specific healthy receipt missing")
	}
	if !reflect.DeepEqual(beforeRelay, s.nodes[relayCert].Desired) || !reflect.DeepEqual(beforeTarget, s.nodes[targetCert].Desired) {
		t.Fatal("reporting health unexpectedly changed listeners")
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
	grant.ExpectedRevision = revision()
	grant.UDP = true
	if _, err = s.ChangeRoute(context.Background(), grant); err != nil {
		t.Fatal("enable three-hop UDP", err)
	}
	if !slices.Contains(s.nodes[targetCert].Desired.Landing.UDPOverTCPListeners, chainID) || !reflect.DeepEqual(beforeRelay, s.nodes[relayCert].Desired) {
		t.Fatal("final UDP authorization missing or relay changed")
	}
	if err = json.Unmarshal(s.nodes[entryCert].Desired.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	udpOutbounds := 0
	for _, o := range cfg.Outbounds {
		if o["mux"] != nil {
			udpOutbounds++
			if o["streamSettings"] == nil {
				t.Fatal("UDP bypassed existing relay")
			}
		}
	}
	if udpOutbounds != 1 {
		t.Fatal("UDP authorization escaped final transport")
	}
}
