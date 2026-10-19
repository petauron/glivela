package control

import (
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	glivela "github.com/petauron/glivela"
)

// One enrolled entry owns one original application identity, not an arbitrary
// collection of other nodes' proxy users. The physical host relation remains
// in the imported application/node references; no identity is regenerated here.
func entryPlanIdentity(plan glivela.XrayPlan) (string, error) {
	invalid := errors.New("control: one exact entry application identity required")
	if len(plan.RealityEndpoints) > 1 || len(plan.HysteriaEndpoints) > 1 {
		return "", invalid
	}
	id := ""
	accept := func(candidate string) bool {
		if !glivela.ValidIdentifier(candidate) {
			return false
		}
		if id == "" {
			id = candidate
		}
		return id == candidate
	}
	for _, endpoint := range plan.RealityEndpoints {
		if !accept(endpoint.EntryID) {
			return "", invalid
		}
		private, err := base64.RawURLEncoding.DecodeString(endpoint.PrivateKey)
		if err != nil {
			return "", invalid
		}
		key, err := ecdh.X25519().NewPrivateKey(private)
		clear(private)
		if err != nil {
			return "", invalid
		}
		public, err := base64.RawURLEncoding.DecodeString(endpoint.PublicKey)
		if err != nil || subtle.ConstantTimeCompare(public, key.PublicKey().Bytes()) != 1 {
			return "", invalid
		}
	}
	for _, endpoint := range plan.HysteriaEndpoints {
		if !accept(endpoint.EntryID) {
			return "", invalid
		}
	}
	if id == "" {
		return "", invalid
	}
	for _, material := range plan.Credentials {
		if material.Credential.EntryID != id {
			return "", invalid
		}
	}
	for _, grant := range plan.Grants {
		if grant.EntryID != id {
			return "", invalid
		}
	}
	return id, nil
}

func validateNodeRole(node Node) error {
	if node.Desired.Entry == nil {
		return validateRouteEntries(node)
	}
	id, err := entryPlanIdentity(*node.Desired.Entry)
	if err != nil || id != node.ID || len(node.RouteEntries) != 0 || len(node.Checks) != 0 {
		return errors.New("control: entry enrollment differs from its application identity")
	}
	return nil
}

// Entry identities may also verify routes, but cannot impersonate landings or
// other entries. Independently enrolled verifier-only identities still work.
func validateEnrollmentRoles(nodes map[string]Node) error {
	entries := map[string]string{}
	for certificate, node := range nodes {
		if node.Desired.Entry != nil {
			entries[node.ID] = certificate
		}
	}
	for _, node := range nodes {
		for id, entry := range node.RouteEntries {
			if certificate, ok := entries[id]; ok && certificate != entry.CertificateID {
				return errors.New("control: entry and verifier certificates disagree")
			}
			if peer, ok := nodes[entry.CertificateID]; ok && (peer.Desired.Entry == nil || peer.ID != id) {
				return errors.New("control: verifier certificate belongs to another node role")
			}
		}
	}
	return nil
}

func invalidateEntryChecks(nodes map[string]Node, id string) {
	for key, node := range nodes {
		if _, ok := node.RouteEntries[id]; ok {
			node.Checks = nil
			nodes[key] = node
		}
	}
}
