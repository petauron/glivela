package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSubscriptionLandingPresentationPreservesPoliciesAndReloads(t *testing.T) {
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

	ctx := context.Background()
	originalBusiness, _ := os.ReadFile(filepath.Join(filepath.Dir(s.path), "business.json"))
	originalNodes, _ := os.ReadFile(s.path)
	before := getSubscription(t, s, "/sub/example-token?format=mihomo", "")
	if before.Code != 200 || !strings.Contains(before.Body.String(), "落地｜") {
		t.Fatal("fixture lacks generated landing name")
	}
	old, err := s.SubscriptionLanding(ctx, "landing-example", nil, nil)
	if err != nil || old != (SubscriptionLanding{}) {
		t.Fatal("new landing presentation", err)
	}
	value := SubscriptionLanding{RegionCode: "US"}
	if _, err = s.SubscriptionLanding(ctx, "landing-example", &old, &value); err != nil {
		t.Fatal(err)
	}
	after := getSubscription(t, s, "/sub/example-token?format=mihomo", "")
	var beforeGraph, afterGraph any
	if yaml.Unmarshal(before.Body.Bytes(), &beforeGraph) != nil || yaml.Unmarshal(after.Body.Bytes(), &afterGraph) != nil {
		t.Fatal("invalid YAML")
	}
	beforeJSON, _ := json.Marshal(beforeGraph)
	afterJSON, _ := json.Marshal(afterGraph)
	expected := strings.ReplaceAll(string(beforeJSON), "落地｜", "🇺🇸 美国｜")
	if after.Code != 200 || string(afterJSON) != expected {
		t.Fatal("subscription changed beyond region label or dependency references")
	}
	if _, err = s.SubscriptionLanding(ctx, "landing-example", &old, &value); err == nil {
		t.Fatal("stale expected accepted")
	}
	bad := SubscriptionLanding{RegionCode: "us"}
	if _, err = s.SubscriptionLanding(ctx, "landing-example", &value, &bad); err == nil {
		t.Fatal("invalid region accepted")
	}
	if _, err = s.SubscriptionLanding(ctx, "entry-example", &old, &value); err == nil {
		t.Fatal("non-landing accepted")
	}
	names := map[string]string{"entry-example": "Example retained entrance"}
	if err = s.ChangeSubscriptionNames(ctx, map[string]string{"entry-example": ""}, names); err != nil {
		t.Fatal(err)
	}
	if got, err := s.SubscriptionLanding(ctx, "landing-example", nil, nil); err != nil || got != value {
		t.Fatal("name update lost landing metadata", err)
	}
	business, _ := os.ReadFile(filepath.Join(filepath.Dir(s.path), "business.json"))
	nodes, _ := os.ReadFile(s.path)
	if !bytes.Equal(business, originalBusiness) || !bytes.Equal(nodes, originalNodes) {
		t.Fatal("presentation changed business or node policies")
	}
	loaded, err := OpenStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = loaded.LoadBusiness(s.business.keyPath); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.subscriptionLandings, s.subscriptionLandings) || !reflect.DeepEqual(loaded.subscriptionNames, s.subscriptionNames) {
		t.Fatal("presentation did not survive reload")
	}
	if err = s.BackupController(time.Now()); err != nil {
		t.Fatal("backup did not retain presentation", err)
	}
}
