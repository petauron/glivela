package control

import (
	"context"
	"encoding/base64"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

func TestIPv6ClientChainPreservesOwnedBusinessAndBindsIdentities(t *testing.T) {
	s, entry, entryCert, _ := subscriptionFixture(t, false)
	landingCert := strings.Repeat("b", 64)
	plan := *artifact(1).Landing
	plan.Sources[0].PublicAddress = "1.1.1.1"
	plan.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), PublicAddress: "9.9.9.9"}
	desired, err := NewDesired(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "landing-example", CertificateID: landingCert, Desired: desired}); err != nil {
		t.Fatal(err)
	}
	before := s.business.material
	change := ClientChainChange{ID: "chain-a", AccountID: "account-example", EntryID: "entry-example", EgressID: "landing-example", Name: "IPv6 chain", Enabled: true, Transport: "ipv6-ss2022", SourceIPv6: "2001:4860:4860::8888", ServerIPv6: "2606:4700:4700::1111", ExpectedRevision: before.Plan.Accounts[0].Account.DesiredRevision}
	// Distinct role IDs on the same enrolled host are still a self-loop.
	s.business.material.References.Nodes = maps.Clone(before.References.Nodes)
	s.business.material.References.Applications = maps.Clone(before.References.Applications)
	s.business.material.References.Nodes["landing-example"] = glivela.ImportNode{Name: "Same host", PreviousStatus: "active"}
	app := s.business.material.References.Applications["entry-example"]
	app.NodeID = "landing-example"
	s.business.material.References.Applications["entry-example"] = app
	if _, err := s.ChangeClientChain(context.Background(), change); err == nil || !strings.Contains(err.Error(), "same host") || len(s.business.material.ClientChains) != 0 {
		t.Fatal("same-host chain was not rejected before changing business state", err)
	}
	s.business.material.References = before.References
	if _, err := s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	after := s.business.material
	// The entry gains a revision-bound speed policy, while the existing proxy
	// configuration, enrollment, credentials and routed peers stay identical.
	proxy := s.nodes[entryCert].Desired.clone()
	proxy.Revision, proxy.Entry.Revision = entry.Revision, entry.Entry.Revision
	proxy.EntryNetwork.SpeedPeers = nil
	if !reflect.DeepEqual(before.TrafficCounters, after.TrafficCounters) || !reflect.DeepEqual(before.SubscriptionTokens, after.SubscriptionTokens) || !reflect.DeepEqual(before.ProtocolSecrets, after.ProtocolSecrets) || !reflect.DeepEqual(before.ResetSchedules, after.ResetSchedules) || !reflect.DeepEqual(before.RetainedSource, after.RetainedSource) || !reflect.DeepEqual(proxy, entry) {
		t.Fatal("client-chain creation changed traffic, subscription, identity, history or entry configuration")
	}
	if len(after.ClientChains) != 1 {
		t.Fatal("chain not retained")
	}
	chain := after.ClientChains[0]
	if chain.EntryCertificateID != entryCert || chain.LandingCertificateID != landingCert {
		t.Fatal("node identities not pinned")
	}
	newLanding := s.nodes[landingCert].Desired.Landing
	if !reflect.DeepEqual(newLanding.Sources, plan.Sources) || newLanding.Transport != plan.Transport || newLanding.EgressIP != plan.EgressIP || len(newLanding.ClientListeners) != 1 {
		t.Fatal("existing transport changed")
	}
	if response := getSubscription(t, s, "/sub/example-token?format=mihomo", ""); response.Code != 200 || !strings.Contains(response.Body.String(), chain.ServerIPv6) || !strings.Contains(response.Body.String(), glivela.SS2022Method) {
		t.Fatal("account did not receive its IPv6 chain")
	}
	if response := getSubscription(t, s, "/sub/other-token?format=mihomo", ""); response.Code != 200 || strings.Contains(response.Body.String(), chain.Key) {
		t.Fatal("another account received the chain key")
	}
	if _, _, err := chainLanding(s.nodes, chain); err != nil {
		t.Fatal("valid enrolled identities rejected", err)
	}

	// Explicit pure IPv6 mode keeps account records but withdraws IPv4 publication.
	pure := *s.nodes[landingCert].Desired.Landing
	pure.IPv6OnlyAddress = chain.ServerIPv6
	pure.EgressIP = "2606:4700::100"
	pure.Sources = append([]landing.Source(nil), pure.Sources...)
	for i := range pure.Sources {
		pure.Sources[i].TCPOnly = true
	}
	pure.Revision++
	desired, err = NewDesired(pure)
	if err != nil {
		t.Fatal(err)
	}
	if desired.LandingRenderVersion != 3 {
		t.Fatal("explicit IPv6 mode lacks its version gate")
	}
	node := s.nodes[landingCert]
	node.Desired = desired
	s.nodes[landingCert] = node
	if _, _, err := chainLanding(s.nodes, chain); err != nil {
		t.Fatal("valid pure IPv6 chain rejected", err)
	}
	oldChain := chain
	oldChain.Transport = glivela.IPv4ClientSS2022
	if clientChainUnavailableReason(s.nodes, oldChain) != "landing_ipv6_only" {
		t.Fatal("IPv4 record lacks unavailable reason")
	}
	if !reflect.DeepEqual(before.TrafficCounters, s.business.material.TrafficCounters) || !reflect.DeepEqual(after.ClientChains, s.business.material.ClientChains) {
		t.Fatal("mode changed account credentials or traffic")
	}
	nodes := make(map[string]Node, len(s.nodes))
	for k, v := range s.nodes {
		nodes[k] = v
	}
	delete(nodes, entryCert)
	if _, _, err := chainLanding(nodes, chain); err == nil {
		t.Fatal("removed certificate retained authorization")
	}
	chain.Transport = "unsupported"
	if _, _, err := chainLanding(s.nodes, chain); err == nil {
		t.Fatal("unsupported transport fell back")
	}
}

func TestIPv4ClientChainSS2022UpgradeRetainsAccountState(t *testing.T) {
	s, _, entryCert, _ := subscriptionFixture(t, false)
	landingCert := strings.Repeat("b", 64)
	plan := *artifact(1).Landing
	plan.Sources[0].PublicAddress = "1.1.1.1"
	plan.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), PublicAddress: "9.9.9.9"}
	desired, err := NewDesired(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "landing-example", CertificateID: landingCert, Desired: desired, RouteEntries: map[string]RouteEntry{"entry-example": {CertificateID: entryCert, Address: "100.64.0.3"}}}); err != nil {
		t.Fatal(err)
	}
	change := ClientChainChange{ID: "chain-a", AccountID: "account-example", EntryID: "entry-example", EgressID: "landing-example", Name: "Existing chain", Enabled: true, ExpectedRevision: s.business.material.Plan.Accounts[0].Account.DesiredRevision}
	if _, err := s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	before := s.business.material
	original := before.ClientChains[0]
	originalLanding := s.nodes[landingCert].Desired.clone()
	originalEntry := s.nodes[entryCert].Desired.clone()
	oldSubscription := getSubscription(t, s, "/sub/example-token?format=mihomo", "")
	change.Transport = glivela.IPv4ClientSS2022
	change.ExpectedRevision = before.Plan.Accounts[0].Account.DesiredRevision
	if _, err := s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	after := s.business.material
	expected := original
	expected.Transport = glivela.IPv4ClientSS2022
	if !reflect.DeepEqual(after.ClientChains, []glivela.ClientChain{expected}) || !reflect.DeepEqual(before.TrafficCounters, after.TrafficCounters) || !reflect.DeepEqual(before.SubscriptionTokens, after.SubscriptionTokens) || !reflect.DeepEqual(before.ProtocolSecrets, after.ProtocolSecrets) || !reflect.DeepEqual(before.ResetSchedules, after.ResetSchedules) || !reflect.DeepEqual(before.RetainedSource, after.RetainedSource) || !reflect.DeepEqual(s.nodes[entryCert].Desired, originalEntry) {
		t.Fatal("cutover changed an identity, entry, credential, ledger or retained history")
	}
	nextLanding := s.nodes[landingCert].Desired.Landing
	if nextLanding.Revision != originalLanding.Revision+1 || !reflect.DeepEqual(nextLanding.Sources, originalLanding.Landing.Sources) || nextLanding.Transport != originalLanding.Landing.Transport || nextLanding.EgressIP != originalLanding.Landing.EgressIP || len(nextLanding.ClientListeners) != 1 || nextLanding.ClientListeners[0] != clientListener(expected, "1.1.1.1") {
		t.Fatal("cutover changed the source, endpoint, existing transport or egress")
	}
	response := getSubscription(t, s, "/sub/example-token?format=mihomo", "")
	if oldSubscription.Code != 200 || response.Code != 200 || !strings.Contains(response.Body.String(), glivela.IPv4ClientSS2022Method) || !strings.Contains(response.Body.String(), original.Key) || strings.Contains(response.Body.String(), "cipher: aes-256-gcm") {
		t.Fatal("subscription did not select only the matching SS2022 method")
	}
	if other := getSubscription(t, s, "/sub/other-token?format=mihomo", ""); strings.Contains(other.Body.String(), original.Key) {
		t.Fatal("another account received the retained key")
	}
	revision := after.Plan.Accounts[0].Account.DesiredRevision
	if revision != change.ExpectedRevision+1 {
		t.Fatal("cutover revision did not advance once")
	}
	if _, err := s.ChangeClientChain(context.Background(), change); err != nil || s.business.material.Plan.Accounts[0].Account.DesiredRevision != revision {
		t.Fatal("retry was not idempotent")
	}
	for _, invalid := range []ClientChainChange{
		{ID: change.ID, AccountID: "account-other", EntryID: change.EntryID, EgressID: change.EgressID, Name: change.Name, Enabled: true, Transport: glivela.IPv4ClientSS2022, ExpectedRevision: revision},
		{ID: change.ID, AccountID: change.AccountID, EntryID: change.EntryID, EgressID: change.EgressID, Name: change.Name, Enabled: true, Transport: "ipv6-ss2022", ExpectedRevision: revision},
		{ID: change.ID, AccountID: change.AccountID, EntryID: change.EntryID, EgressID: change.EgressID, Name: "stale change", Enabled: true, Transport: glivela.IPv4ClientSS2022, ExpectedRevision: change.ExpectedRevision},
	} {
		if _, err := s.ChangeClientChain(context.Background(), invalid); err == nil {
			t.Fatal("cross-account, alternate transport or stale mutation accepted")
		}
	}
	// A landing cutover retains original per-chain configuration and the unique
	// ledger. Explicit recovery advances configuration; it never restores usage.
	reportRuntime(t, s, landingCert, s.nodes[landingCert].Desired)
	retained := s.business.material
	share := ClientChainChange{AccountID: change.AccountID, EgressID: change.EgressID, ShareLanding: true, ExpectedRevision: revision}
	if _, err := s.ChangeClientChain(context.Background(), share); err != nil {
		t.Fatal(err)
	}
	shared := s.business.material
	effective, err := shared.EffectiveClientChain(shared.ClientChains[0])
	if err != nil || !effective.Shared || effective.Port != 24000 || effective.Key == original.Key || effective.Validate() != nil {
		t.Fatal("shared client credential invalid", err)
	}
	if !reflect.DeepEqual(retained.ClientChains, shared.ClientChains) || !reflect.DeepEqual(retained.TrafficCounters, shared.TrafficCounters) || !reflect.DeepEqual(retained.ProtocolSecrets, shared.ProtocolSecrets) || !reflect.DeepEqual(retained.SubscriptionTokens, shared.SubscriptionTokens) || !reflect.DeepEqual(retained.RetainedSource, shared.RetainedSource) {
		t.Fatal("shared cutover changed retained state")
	}
	if s.nodes[landingCert].Desired.Landing.Transport != plan.Transport || !reflect.DeepEqual(s.nodes[entryCert].Desired, originalEntry) {
		t.Fatal("shared cutover changed server forwarding or entry")
	}
	response = getSubscription(t, s, "/sub/example-token?format=mihomo", "")
	if response.Code != 200 || !strings.Contains(response.Body.String(), glivela.SS2022Method) || !strings.Contains(response.Body.String(), effective.Key) || strings.Contains(response.Body.String(), original.Key) {
		t.Fatal("shared subscription mismatch")
	}
	if other := getSubscription(t, s, "/sub/other-token?format=mihomo", ""); strings.Contains(other.Body.String(), effective.Key) {
		t.Fatal("shared secret disclosed to another account")
	}
	if _, err := s.ChangeClientChain(context.Background(), share); err != nil || s.business.material.ClientLandings[change.EgressID] != shared.ClientLandings[change.EgressID] {
		t.Fatal("shared retry changed key", err)
	}
	conflict := share
	conflict.AccountID = "account-other"
	conflict.ExpectedRevision = s.business.material.Plan.Accounts[1].Account.DesiredRevision
	if _, err := s.ChangeClientChain(context.Background(), conflict); err == nil {
		t.Fatal("cross-account shared key accepted")
	}
	restore := ClientChainChange{AccountID: change.AccountID, EgressID: change.EgressID, RestoreLanding: true, ExpectedRevision: s.business.material.Plan.Accounts[0].Account.DesiredRevision}
	if _, err := s.ChangeClientChain(context.Background(), restore); err != nil {
		t.Fatal(err)
	}
	recovered := s.business.material
	if len(recovered.ClientLandings) != 0 || !reflect.DeepEqual(recovered.ClientChains, retained.ClientChains) || !reflect.DeepEqual(recovered.TrafficCounters, retained.TrafficCounters) || recovered.Plan.Accounts[0].Account.DesiredRevision != restore.ExpectedRevision+1 {
		t.Fatal("forward recovery changed usage or original config")
	}

}

func TestIPv6OnlyModePreservesOtherNodesAndWithholdsIPv4(t *testing.T) {
	s, _, entryCert, _ := subscriptionFixture(t, false)
	cert := strings.Repeat("b", 64)
	p := *artifact(1).Landing
	p.Sources[0].PublicAddress = "1.1.1.1"
	p.Transport = glivela.PrivateTransport{Protocol: "ss2022", Key: base64.StdEncoding.EncodeToString(make([]byte, 16)), PublicAddress: "9.9.9.9"}
	d, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(Node{ID: "landing-example", CertificateID: cert, Desired: d, RouteEntries: map[string]RouteEntry{"entry-example": {CertificateID: entryCert, Address: "100.64.0.3"}}}); err != nil {
		t.Fatal(err)
	}
	change := ClientChainChange{ID: "chain-a", AccountID: "account-example", EntryID: "entry-example", EgressID: "landing-example", Name: "Retained IPv4", Enabled: true, ExpectedRevision: s.business.material.Plan.Accounts[0].Account.DesiredRevision}
	if _, err := s.ChangeClientChain(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	before := s.nodes[entryCert].Desired.clone()
	m := s.business.material
	chain := m.ClientChains[0]
	n := s.nodes[cert]
	copy := n.Desired.clone()
	p = *copy.Landing
	p.Revision++
	p.IPv6OnlyAddress = "2606:4700:4700::1111"
	p.EgressIP = "2606:4700::100"
	for i := range p.Sources {
		p.Sources[i].TCPOnly = true
	}
	n.Desired, err = NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	s.nodes[cert] = n
	projected, _, err := projectBusinessEntries(s.nodes, m, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projected[entryCert].Desired, before) || !reflect.DeepEqual(projected[cert].Desired, n.Desired) {
		t.Fatal("unavailable IPv4 rewrote retained node policy")
	}
	response := getSubscription(t, s, "/sub/example-token?format=mihomo", "")
	if response.Code != 200 || strings.Contains(response.Body.String(), chain.Key) {
		t.Fatal("inactive IPv4 chain was published")
	}
	if _, _, _, err := s.chainSpeedPairLocked(change.EntryID, change.EgressID, false); err == nil {
		t.Fatal("inactive IPv4 test path was authorized")
	}
	view := s.Business()
	if len(view.ClientChains) != 1 || view.ClientChains[0].UnavailableReason != "landing_ipv6_only" || !view.ClientChains[0].Enabled {
		t.Fatal("retained record lost its reason or configured switch")
	}
	if !reflect.DeepEqual(m, s.business.material) {
		t.Fatal("account configuration or ledger changed")
	}
}
