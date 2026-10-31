package control

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

func registrationFixture(t *testing.T, s *Store) EndpointRegistration {
	t.Helper()
	e := s.business.material.Endpoints[0]
	e.Reality.ID = "endpoint-new"
	e.Reality.EntryID = "entry-new"
	e.Reality.InboundTag = "entry-new"
	e.Reality.ListenAddress = "100.64.0.8"
	e.ServiceID = "service-new"
	e.DesiredRevision = 1
	e.AppliedRevision = 0
	e.UsedBytes = 0
	e.Retired = false
	e.LegacyRetired = false
	e.HistoricalHealthy = false
	e.RuntimeCertificateID = ""
	e.RuntimeConfigSHA256 = ""
	e.PreviousStatus = "pending"
	e.RealityChanges = nil
	e.Hysteria = nil
	e.HysteriaEnabled = false
	e.CertificateNotAfter = ""
	e.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	e.UpdatedAt = e.CreatedAt
	return EndpointRegistration{CertificateID: strings.Repeat("d", 64), NativeEgress: glivela.EgressIPv6Only, Endpoint: e, NodeID: "host-new", Node: glivela.ImportNode{Name: "New host", PreviousStatus: "active", PrivateAddress: "100.64.0.8"}, Application: glivela.ImportApplication{Name: "New host", NodeID: "host-new", Runtime: "host", PreviousStatus: "pending"}, Service: glivela.ImportService{ApplicationID: "entry-new", Name: "proxy", DisplayName: "New host", Protocol: "tcp", ContainerPort: e.Reality.ListenPort, HostPort: e.Reality.AdvertisePort, RegionCode: "SG", Timezone: "UTC"}, Accounts: []string{"account-example"}}
}

func TestFreshEndpointKeepsAccountSubscriptionAndLedger(t *testing.T) {
	s, _, _, _ := subscriptionFixture(t, true)
	before := s.business.material
	input := registrationFixture(t, s)
	if err := s.RegisterEndpoint(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	after := s.business.material
	if len(after.Endpoints) != len(before.Endpoints)+1 || len(after.Plan.Accounts) != len(before.Plan.Accounts) || !reflect.DeepEqual(after.SubscriptionTokens, before.SubscriptionTokens) || !reflect.DeepEqual(after.ResetSchedules, before.ResetSchedules) {
		t.Fatal("onboarding replaced account, subscription or reset schedule")
	}
	for id, c := range before.TrafficCounters {
		if after.TrafficCounters[id] != c {
			t.Fatal("existing traffic reset")
		}
	}
	for i, a := range before.Plan.Accounts {
		n := after.Plan.Accounts[i]
		if a.Account.ID != "account-example" {
			if !reflect.DeepEqual(a, n) {
				t.Fatal("unselected account changed")
			}
			continue
		}
		oldCredentials := map[string]glivela.Credential{}
		for _, c := range n.Credentials {
			oldCredentials[c.ID] = c
		}
		oldUsage := map[string]glivela.UsageMember{}
		for _, u := range n.Usage {
			oldUsage[u.CredentialID] = u
		}
		for _, c := range a.Credentials {
			if oldCredentials[c.ID] != c {
				t.Fatal("existing credential changed")
			}
		}
		for _, u := range a.Usage {
			if oldUsage[u.CredentialID] != u {
				t.Fatal("existing usage changed")
			}
		}
		if len(n.Credentials) != len(a.Credentials)+1 || n.Account.Plan != a.Account.Plan {
			t.Fatal("existing authorization or usage changed")
		}
	}
	written := businessBytes(t, s)
	if err := s.RegisterEndpoint(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if string(written) != string(businessBytes(t, s)) {
		t.Fatal("retry regenerated credentials or rewrote accounting")
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal("registered endpoint did not survive controller restart", err)
	}
	if !reflect.DeepEqual(loaded.business.material, s.business.material) || loaded.nodes[input.CertificateID].Desired.Entry == nil {
		t.Fatal("restart lost business or role identity")
	}
	input.Endpoint.Reality.AdvertisePort++
	if s.RegisterEndpoint(context.Background(), input) == nil {
		t.Fatal("retry silently replaced endpoint")
	}
}

func TestFreshEndpointRejectsUnknownAccountAndImportedReadiness(t *testing.T) {
	for _, fault := range []string{"account", "used", "receipt", "role", "duplicate-account"} {
		t.Run(fault, func(t *testing.T) {
			s, _, _, _ := subscriptionFixture(t, true)
			in := registrationFixture(t, s)
			before := businessBytes(t, s)
			switch fault {
			case "account":
				in.Accounts = []string{"missing"}
			case "used":
				in.Endpoint.UsedBytes = 1
			case "receipt":
				in.Endpoint.AppliedRevision = 1
			case "role":
				in.Application.Runtime = "docker"
			case "duplicate-account":
				in.Accounts = append(in.Accounts, in.Accounts[0])
			}
			if s.RegisterEndpoint(context.Background(), in) == nil {
				t.Fatal("invalid registration accepted")
			}
			if string(before) != string(businessBytes(t, s)) {
				t.Fatal("rejected onboarding changed live business")
			}
		})
	}
}

func TestFreshEndpointRetainsExplicitExistingExitPolicies(t *testing.T) {
	for _, policy := range []glivela.EgressPolicy{glivela.EgressAuto, glivela.EgressIPv4Only, glivela.EgressIPv6Only, "", "unsupported"} {
		t.Run(string(policy), func(t *testing.T) {
			s, _, _, _ := subscriptionFixture(t, true)
			input := registrationFixture(t, s)
			input.NativeEgress = policy
			err := s.RegisterEndpoint(context.Background(), input)
			valid := policy != "" && policy.Validate() == nil
			if (err == nil) != valid {
				t.Fatalf("exit policy %q: %v", policy, err)
			}
			if valid && s.nodes[input.CertificateID].Desired.Entry.NativeEgress != policy {
				t.Fatal("requested exit policy changed")
			}
		})
	}
}

func TestMaintenanceRealityChangeKeepsSubscriptionPaused(t *testing.T) {
	s, d, certificate, _ := subscriptionFixture(t, false)
	if err := s.SetAvailability("entry-example", "maintenance", time.Time{}, s.availability.Revision); err != nil {
		t.Fatal(err)
	}
	pause := s.availability
	report := func(desired Desired) {
		now := time.Now().UTC()
		observation := healthyEntryObservation(desired, now)
		observation.Traffic = quotaReceipt(desired, now.Add(-time.Second), now, 0).Traffic
		if _, err := s.Exchange(context.Background(), certificate, &observation); err != nil {
			t.Fatal(err)
		}
	}
	report(d)
	node := s.nodes[certificate]
	endpoint := s.business.material.Endpoints[0]
	if !s.realityTargetRuntimeReady(node, endpoint, time.Now()) || s.availableRuntime(node, time.Now()) {
		t.Fatal("maintenance readiness and publication were not separated")
	}
	for _, reason := range []string{"traffic-exhausted"} {
		blocked := s.availability.Nodes[node.ID]
		blocked.Reason = reason
		s.availability.Nodes[node.ID] = blocked
		if s.realityTargetRuntimeReady(node, endpoint, time.Now()) {
			t.Fatal("exhaustion allowed target change")
		}
		blocked.Reason = "maintenance"
		s.availability.Nodes[node.ID] = blocked
	}
	exhausted := endpoint
	exhausted.TotalBytes = 100
	exhausted.UsedBytes = 100
	if s.realityTargetRuntimeReady(node, exhausted, time.Now()) {
		t.Fatal("maintenance hid exhausted quota")
	}
	stale := node
	stale.ReportedAt = time.Now().Add(-2 * time.Minute)
	if s.realityTargetRuntimeReady(stale, endpoint, time.Now()) {
		t.Fatal("stale runtime allowed target change")
	}
	tokens := s.business.material.SubscriptionTokens
	secrets := s.business.material.ProtocolSecrets
	counters := s.business.material.TrafficCounters
	view, err := s.ChangeRealityTarget(context.Background(), RealityChangeInput{EntryID: node.ID, ExpectedRevision: node.Desired.Revision, Action: "apply", TargetHost: "site.example.net", ServerName: "site.example.net", LocalTLSOrigin: true})
	if err != nil {
		t.Fatal(err)
	}
	report(s.nodes[certificate].Desired)
	view, err = s.ChangeRealityTarget(context.Background(), RealityChangeInput{EntryID: node.ID, ExpectedRevision: view.Revision, Action: "accept", VerifiedAt: time.Now().UTC(), PublicationChecked: true, EvidenceSHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pause, s.availability) || !s.suspended(node.ID, time.Now()) {
		t.Fatal("target change resumed publication")
	}
	if !reflect.DeepEqual(tokens, s.business.material.SubscriptionTokens) || !reflect.DeepEqual(secrets, s.business.material.ProtocolSecrets) {
		t.Fatal("target change replaced credentials")
	}
	for id, before := range counters {
		after := s.business.material.TrafficCounters[id]
		if after.UploadBytes < before.UploadBytes || after.DownloadBytes < before.DownloadBytes {
			t.Fatal("target change reset traffic")
		}
	}
	if response := getSubscription(t, s, "/sub/example-token?format=mihomo", ""); response.Code != 503 {
		t.Fatalf("paused entrance was published: %d", response.Code)
	}
	if view.State != "accepted" {
		t.Fatalf("change not accepted: %s", view.State)
	}
}
