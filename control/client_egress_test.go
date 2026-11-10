package control

import (
	"context"
	"encoding/base64"
	glivela "github.com/petauron/glivela"
	"reflect"
	"strings"
	"testing"
)

func TestSingleLandingClientExitPreservesIdentityAndAccount(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, false)
	p := *artifact(1).Landing
	p.EgressIP = "2606:4700::100"
	p.Sources[0].TCPOnly = true
	p.Sources[0].PublicAddress = "1.1.1.1"
	p.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), PublicAddress: "9.9.9.9"}
	old, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	cert := strings.Repeat("b", 64)
	if err = s.Put(Node{ID: "landing-example", CertificateID: cert, Desired: old}); err != nil {
		t.Fatal(err)
	}
	change := ClientChainChange{ID: "retained", AccountID: "account-example", EntryID: "entry-example", EgressID: "landing-example", Name: "Retained IPv6 exit", Enabled: true, Transport: "ipv6-ss2022", SourceIPv6: "2001:4860:4860::8888", ServerIPv6: "2606:4700:4700::1111", ExpectedRevision: s.business.material.Plan.Accounts[0].Account.DesiredRevision}
	if _, err = s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	before := s.business.material
	retained := s.nodes[cert].Desired.Landing.ClientListeners[0]
	nodeCount := len(s.nodes)
	ip := "9.9.9.9"
	change.ID = "v4-exit"
	change.Name = "IPv4 final through IPv6"
	change.EgressIP = &ip
	change.ExpectedRevision = before.Plan.Accounts[0].Account.DesiredRevision
	if _, err = s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	after := s.business.material
	plan := s.nodes[cert].Desired.Landing
	if len(s.nodes) != nodeCount || s.nodes[cert].ID != "landing-example" || plan.EgressIP != p.EgressIP || plan.Transport != p.Transport || !reflect.DeepEqual(plan.Sources, p.Sources) || s.nodes[cert].Desired.LandingRenderVersion != 6 || len(plan.ClientListeners) != 2 || plan.ClientListeners[0] != retained || plan.ClientListeners[1].EgressIP != ip {
		t.Fatal("default relay, enrollment or fixed exits changed")
	}
	if !reflect.DeepEqual(before.TrafficCounters, after.TrafficCounters) || !reflect.DeepEqual(before.SubscriptionTokens, after.SubscriptionTokens) || !reflect.DeepEqual(before.ProtocolSecrets, after.ProtocolSecrets) || !reflect.DeepEqual(before.ResetSchedules, after.ResetSchedules) || !reflect.DeepEqual(before.RetainedSource, after.RetainedSource) {
		t.Fatal("retained business state changed")
	}
	// Omitting the optional field during a rename/toggle must preserve it.
	change.EgressIP = nil
	change.Name = "Renamed fixed exit"
	change.ExpectedRevision = after.Plan.Accounts[0].Account.DesiredRevision
	if _, err = s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	if s.business.material.ClientChains[1].EgressIP != ip || s.nodes[cert].Desired.Landing.ClientListeners[1].EgressIP != ip {
		t.Fatal("omitted update reset a pinned exit")
	}
	ip = "100.64.0.99"
	change.EgressIP = &ip
	change.ExpectedRevision = s.business.material.Plan.Accounts[0].Account.DesiredRevision
	beforeDesired := s.nodes[cert].Desired.clone()
	beforeRevision := change.ExpectedRevision
	if _, err = s.ChangeClientChain(context.Background(), change); err == nil {
		t.Fatal("invalid exit accepted")
	}
	if s.business.material.Plan.Accounts[0].Account.DesiredRevision != beforeRevision || !reflect.DeepEqual(beforeDesired, s.nodes[cert].Desired) {
		t.Fatal("rejected change altered runtime state")
	}
}
