package control

import (
	"bytes"
	"encoding/json"
	glivela "github.com/petauron/glivela"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPublicEgressUpgradePreservesUDPPolicyQuotaAndHistoricalArtifacts(t *testing.T) {
	for _, version := range []uint8{0, 1} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			q, current, _ := quotaFixture(t)
			old, err := newEntryDesiredVersion(*current.Entry, *current.EntryNetwork, version)
			if err != nil {
				t.Fatal(err)
			}
			q.Base = old.clone()
			before := q.clone()
			original, _ := json.Marshal(old)
			s := store(t)
			certificate := strings.Repeat("a", 64)
			if err := s.Put(Node{ID: "entry-example", CertificateID: certificate, Desired: old, EntryQuota: q}); err != nil {
				t.Fatal(err)
			}
			if err := s.UpgradePublicEgress(); err != nil {
				t.Fatal(err)
			}
			got := s.nodes[certificate]
			if got.Desired.Revision != old.Revision+1 || got.Desired.EntryRenderVersion != version|2 || got.Desired.Validate() != nil {
				t.Fatal("wrong forward policy transition")
			}
			if !reflect.DeepEqual(got.Desired.Entry.Credentials, old.Entry.Credentials) || !reflect.DeepEqual(got.Desired.EntryNetwork, old.EntryNetwork) {
				t.Fatal("identity or source policy changed")
			}
			compare := got.EntryQuota.clone()
			compare.Base = before.Base
			if !reflect.DeepEqual(compare, before) {
				t.Fatal("quota, counter or reset schedule changed")
			}
			unchanged, _ := json.Marshal(old)
			if !bytes.Equal(original, unchanged) || old.Validate() != nil {
				t.Fatal("old artifact was rewritten or no longer verifies")
			}
			raw, err := os.ReadFile(s.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.UpgradePublicEgress(); err != nil {
				t.Fatal(err)
			}
			retry, _ := os.ReadFile(s.path)
			if !bytes.Equal(raw, retry) {
				t.Fatal("migration retry changed state")
			}
			reopened, err := OpenStore(s.path)
			if err != nil || reopened.nodes[certificate].Desired.Validate() != nil {
				t.Fatal("migrated policy cannot reload", err)
			}
		})
	}
}

func TestPublicEgressUpgradePreservesOwnedBusinessAndSubscriptionIdentity(t *testing.T) {
	s, d, cert, _ := subscriptionFixture(t, true)
	old, err := newEntryDesiredVersion(*d.Entry, *d.EntryNetwork, 1)
	if err != nil {
		t.Fatal(err)
	}
	node := s.nodes[cert]
	node.Desired = old
	node.Receipt = nil
	s.nodes[cert] = node
	before := s.business.material
	beforeFile := businessBytes(t, s)
	availability, _ := json.Marshal(s.availability)
	if err := s.UpgradePublicEgress(); err != nil {
		t.Fatal(err)
	}
	afterAvailability, _ := json.Marshal(s.availability)
	if !reflect.DeepEqual(before, s.business.material) || !bytes.Equal(beforeFile, businessBytes(t, s)) || !bytes.Equal(availability, afterAvailability) {
		t.Fatal("migration changed account, subscription, availability or accounting")
	}
	if s.nodes[cert].Desired.Entry.PublicSSH != nil || s.nodes[cert].CertificateID != cert {
		t.Fatal("retired SSH policy or changed identity")
	}
	changed := s.nodes[cert].Desired.clone()
	changed.Entry.PublicSSH = &glivela.PublicSSHPolicy{AddressesComplete: true, HostPublicAddresses: []string{"8.8.8.8"}}
	if changed.Validate() == nil {
		t.Fatal("retired policy accepted in current artifact")
	}
}

func TestPublicEgressUpgradeAdvancesHistoricalLandingWithoutChangingSources(t *testing.T) {
	old := artifact(7)
	var err error
	old.DesiredArtifact, err = old.Landing.ArtifactVersion(0)
	old.LandingRenderVersion = 0
	if err != nil || old.Validate() != nil {
		t.Fatal("old landing artifact invalid", err)
	}
	s := store(t)
	cert := strings.Repeat("b", 64)
	if err := s.Put(Node{ID: "landing-example", CertificateID: cert, Desired: old}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpgradePublicEgress(); err != nil {
		t.Fatal(err)
	}
	got := s.nodes[cert].Desired
	if got.Revision != 8 || got.LandingRenderVersion != 1 || got.Validate() != nil || !reflect.DeepEqual(got.Landing.Sources, old.Landing.Sources) || got.Landing.EgressIP != old.Landing.EgressIP {
		t.Fatal("landing upgrade changed source or exit authority")
	}
	if old.Validate() != nil {
		t.Fatal("historical landing became unreadable")
	}
}

func TestPublicEgressStartupDoesNotActivateLandingDNS(t *testing.T) {
	for _, version := range []uint8{1, 2} {
		s := store(t)
		plan := *artifact(7).Landing
		plan.EgressIP = "2606:4700::100"
		for i := range plan.Sources {
			plan.Sources[i].TCPOnly = true
		}
		desired, err := newLandingDesiredVersion(plan, version)
		if err != nil {
			t.Fatal(err)
		}
		cert := strings.Repeat("b", 64)
		if err := s.Put(Node{ID: "landing-example", CertificateID: cert, Desired: desired}); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(s.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.UpgradePublicEgress(); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(s.path)
		if err != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(s.nodes[cert].Desired, desired) {
			t.Fatal("startup changed an unselected landing", version, err)
		}
		reopened, err := OpenStore(s.path)
		if err != nil || reopened.nodes[cert].Desired.Validate() != nil {
			t.Fatal("retained artifact cannot reload", version, err)
		}
	}
}
