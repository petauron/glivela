package control

import (
	"context"
	"encoding/base64"
	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
	"reflect"
	"strings"
	"testing"
)

func TestClientOnlyLandingPreservesCohostedIPv6Relay(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	plan := *artifact(1).Landing
	plan.EgressIP = "2606:4700::100"
	plan.Sources[0].PublicAddress = "1.1.1.1"
	plan.Sources[0].TCPOnly = true
	plan.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), PublicAddress: "9.9.9.9"}
	old, err := NewDesired(plan)
	if err != nil {
		t.Fatal(err)
	}
	relayCert := strings.Repeat("b", 64)
	if err = s.Put(Node{ID: "relay-example", CertificateID: relayCert, Desired: old}); err != nil {
		t.Fatal(err)
	}
	plan.ClientOnly = true
	plan.EgressIP = "9.9.9.9"
	next, err := NewDesired(plan)
	if err != nil || next.LandingRenderVersion != 5 {
		t.Fatal("client-only format not selected", err)
	}
	if err = s.Put(Node{ID: "landing-example", CertificateID: strings.Repeat("c", 64), Desired: next}); err != nil {
		t.Fatal(err)
	}
	before := s.business.material
	change := ClientChainChange{ID: "client-only", AccountID: "account-example", EntryID: "entry-example", EgressID: "landing-example", Name: "IPv4 exit through IPv6 transport", Enabled: true, Transport: "ipv6-ss2022", SourceIPv6: "2001:4860:4860::8888", ServerIPv6: "2606:4700:4700::1111", ExpectedRevision: before.Plan.Accounts[0].Account.DesiredRevision}
	if _, err = s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.nodes[relayCert].Desired, old) {
		t.Fatal("existing IPv6 relay changed")
	}
	after := s.business.material
	if !reflect.DeepEqual(before.TrafficCounters, after.TrafficCounters) || !reflect.DeepEqual(before.SubscriptionTokens, after.SubscriptionTokens) || !reflect.DeepEqual(before.ProtocolSecrets, after.ProtocolSecrets) || !reflect.DeepEqual(before.ResetSchedules, after.ResetSchedules) {
		t.Fatal("existing account state changed")
	}
	for _, n := range s.nodes {
		if n.ID == "landing-example" && (!n.Desired.Landing.ClientOnly || n.Desired.Landing.EgressIP != "9.9.9.9") {
			t.Fatal("new landing lost isolated IPv4 policy")
		}
	}
}

func TestCohostedLandingPortAllocationAndConflictRejection(t *testing.T) {
	old := *artifact(1).Landing
	old.Transport = glivela.PrivateTransport{PublicAddress: "9.9.9.9"}
	old.ClientListeners = []landing.ClientListener{{ID: "relay-chain", Port: 24000, Transport: "ipv6-ss2022", Address: "2606:4700:4700::1111"}}
	fresh := old
	fresh.ClientOnly = true
	fresh.ClientListeners = nil
	nodes := map[string]Node{"old": {ID: "relay", Desired: Desired{Landing: &old}}, "new": {ID: "client", Desired: Desired{Landing: &fresh}}}
	m := glivela.ImportMaterial{ClientChains: []glivela.ClientChain{{ID: "retained", EgressID: "elsewhere", Relay: &glivela.ClientChainRelay{NodeID: "relay", Port: 24000}}}}
	if port := clientChainPort(m, nodes, "client"); port != 24001 {
		t.Fatalf("existing relay port was reused: %d", port)
	}
	fresh.ClientListeners = []landing.ClientListener{{ID: "new-chain", Port: 24000, Transport: "ipv6-ss2022", Address: "2606:4700:4700::1111"}}
	if validateClientOnlyListeners(nodes) == nil {
		t.Fatal("cohosted worker listener conflict accepted")
	}
	fresh.ClientListeners[0].Port = 24001
	if err := validateClientOnlyListeners(nodes); err != nil {
		t.Fatal(err)
	}
	fresh.Transport.PublicAddress = "8.8.8.8"
	fresh.ClientListeners = nil
	if port := clientChainPort(m, nodes, "client"); port != 24000 {
		t.Fatal("unrelated address lost its port")
	}
}
