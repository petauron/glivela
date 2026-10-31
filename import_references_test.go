package glivela

import (
	"strings"
	"testing"
)

func TestImportReferencesPreserveMultibyteDisplayNames(t *testing.T) {
	m := importFixture(t)
	s := m.References.Services["service-a"]
	s.DisplayName = strings.Repeat("节", MaxDisplayNameLength)
	m.References.Services["service-a"] = s
	m.References.LandingSelection = &ImportLandingSelection{NodeIDs: []string{"node-entry-a"}, LandingNameSuffixes: map[string]string{"node-entry-a": s.DisplayName}, Revision: 1}
	if err := m.Validate(); err != nil {
		t.Fatal("valid character-bounded label was treated as byte-bounded", err)
	}
}

func TestImportReferencesRetainUnknownNetworkObservations(t *testing.T) {
	m := importFixture(t)
	n := m.References.Nodes["node-entry-a"]
	n.EgressAddressesJSON = []byte(`null`)
	n.PeerJSON = []byte(`null`)
	m.References.Nodes["node-entry-a"] = n
	if err := m.Validate(); err != nil {
		t.Fatal("valid unknown historical observation discarded", err)
	}
	if string(m.References.Nodes["node-entry-a"].EgressAddressesJSON) != "null" {
		t.Fatal("unknown observation was initialized as an empty list")
	}
}

func TestImportReferencesRejectMissingAndChangedBindings(t *testing.T) {
	for name, change := range map[string]func(*ImportMaterial){
		"node":    func(m *ImportMaterial) { delete(m.References.Nodes, "node-entry-a") },
		"app":     func(m *ImportMaterial) { delete(m.References.Applications, "entry-a") },
		"service": func(m *ImportMaterial) { delete(m.References.Services, "service-a") },
		"service owner": func(m *ImportMaterial) {
			s := m.References.Services["service-a"]
			s.ApplicationID = "other-app"
			m.References.Services["service-a"] = s
		},
		"invalid saved peer": func(m *ImportMaterial) {
			n := m.References.Nodes["node-entry-a"]
			n.PeerJSON = []byte(`[]`)
			m.References.Nodes["node-entry-a"] = n
		},
		"missing selection node": func(m *ImportMaterial) {
			m.References.LandingSelection = &ImportLandingSelection{NodeIDs: []string{"missing-node"}, Revision: 1}
		},
		"missing selection list": func(m *ImportMaterial) { m.References.LandingSelection = &ImportLandingSelection{Revision: 1} },
	} {
		t.Run(name, func(t *testing.T) {
			m := importFixture(t)
			change(&m)
			if m.Validate() == nil {
				t.Fatal("invalid reference graph accepted")
			}
		})
	}
}
