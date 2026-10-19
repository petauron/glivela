package glivela

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io"
)

// ImportMaterial is one atomic, sensitive handover checkpoint. RetainedSource
// is immutable migration evidence/history, never a second live configuration
// source. Do not send this material in a node receipt or publish it in logs.
type ImportMaterial struct {
	SourceSHA256       string                           `json:"sourceSha256"`
	RetainedSource     json.RawMessage                  `json:"retainedSource"`
	Endpoints          []ImportEndpoint                 `json:"endpoints"`
	References         ImportReferences                 `json:"references"`
	Plan               ImportPlan                       `json:"plan"`
	SubscriptionTokens map[string]string                `json:"subscriptionTokens"`
	ProtocolSecrets    map[string]string                `json:"protocolSecrets"`
	HysteriaSecrets    map[string]string                `json:"hysteriaSecrets"`
	ResetSchedules     map[string]ImportResetSchedule   `json:"resetSchedules"`
	TrafficCounters    map[string]ImportTrafficCounters `json:"trafficCounters"`
	Ownership          *BusinessOwnership               `json:"ownership,omitempty"`
}

func (m ImportMaterial) Validate() error {
	if _, err := m.sourceSnapshot(); err != nil {
		return err
	}
	if m.Ownership != nil {
		if err := m.Ownership.Validate(m.SourceSHA256); err != nil {
			return err
		}
	}
	plan, err := PlanImport(m.Plan.Accounts)
	if err != nil || plan.SHA256 != m.Plan.SHA256 {
		return errors.New("glivela: import inventory differs")
	}
	if err := m.validateAccountState(); err != nil {
		return err
	}
	credentials, hysteria := 0, 0
	for _, item := range plan.Accounts {
		if SubscriptionTokenFingerprint(m.SubscriptionTokens[item.Account.ID]) != item.SubscriptionTokenFingerprint {
			return errors.New("glivela: subscription identity missing or changed")
		}
		for _, credential := range item.Credentials {
			credentials++
			material := CredentialMaterial{Credential: credential, ProtocolID: m.ProtocolSecrets[credential.ID], HysteriaAuth: m.HysteriaSecrets[credential.ID], HysteriaIdentity: item.HysteriaIdentities[credential.ID]}
			if material.Validate() != nil {
				return errors.New("glivela: protocol identity missing or changed")
			}
		}
		for id, expected := range item.HysteriaIdentities {
			hysteria++
			if Identity(m.HysteriaSecrets[id]) != expected {
				return errors.New("glivela: Hysteria identity missing or changed")
			}
		}
	}
	if len(m.SubscriptionTokens) != len(plan.Accounts) || len(m.ProtocolSecrets) != credentials || len(m.HysteriaSecrets) != hysteria {
		return errors.New("glivela: unreferenced import credentials")
	}
	if err := m.validateEndpoints(); err != nil {
		return err
	}
	return m.validateReferences()
}

// Only the archive identity header is interpreted here. Legacy table formats
// are read by the one-time offline tool, not by the controller or node runtime.
func (m ImportMaterial) sourceSnapshot() (string, error) {
	var header struct {
		Version      int    `json:"version"`
		Schema       int    `json:"sourceSchema"`
		SnapshotID   string `json:"snapshotId"`
		SourceSHA256 string `json:"sourceSha256"`
	}
	if len(m.RetainedSource) > maxImportMaterial || json.Unmarshal(m.RetainedSource, &header) != nil || header.Version != 1 || header.Schema != 113 && header.Schema != 114 && header.Schema != 115 || !ValidIdentifier(header.SnapshotID) || !ValidIdentity(m.SourceSHA256) || header.SourceSHA256 != m.SourceSHA256 {
		return "", errors.New("glivela: missing or changed source snapshot identity")
	}
	return header.SnapshotID, nil
}

const maxImportMaterial = 64 << 20
const importMaterialContext = "glivela-business-handover-v1"

// SealImportMaterial uses standard authenticated encryption with an externally
// supplied 256-bit transfer key. Nonces come from Go's GCM implementation. The
// authenticated snapshot identifier prevents swapping material between exports.
// Successful decryption is not evidence that the legacy writer is fenced.
func SealImportMaterial(m ImportMaterial, key []byte, snapshotID string) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if source, _ := m.sourceSnapshot(); source != snapshotID {
		return nil, errors.New("glivela: source snapshot differs from transfer identity")
	}
	aead, err := importCipher(key, snapshotID)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > maxImportMaterial {
		return nil, errors.New("glivela: import material too large")
	}
	defer clear(raw)
	return aead.Seal(nil, nil, raw, []byte(importMaterialContext+":"+snapshotID)), nil
}

func OpenImportMaterial(sealed, key []byte, snapshotID string) (ImportMaterial, error) {
	aead, err := importCipher(key, snapshotID)
	if err != nil {
		return ImportMaterial{}, err
	}
	if len(sealed) > maxImportMaterial+aead.Overhead() {
		return ImportMaterial{}, errors.New("glivela: import material too large")
	}
	raw, err := aead.Open(nil, nil, sealed, []byte(importMaterialContext+":"+snapshotID))
	if err != nil {
		return ImportMaterial{}, errors.New("glivela: import authentication failed")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var m ImportMaterial
	var extra any
	if decoder.Decode(&m) != nil || decoder.Decode(&extra) != io.EOF || m.Validate() != nil {
		return ImportMaterial{}, errors.New("glivela: invalid import material")
	}
	if source, _ := m.sourceSnapshot(); source != snapshotID {
		return ImportMaterial{}, errors.New("glivela: source snapshot differs from transfer identity")
	}
	return m, nil
}

func importCipher(key []byte, snapshotID string) (cipher.AEAD, error) {
	if len(key) != 32 || !ValidIdentifier(snapshotID) {
		return nil, errors.New("glivela: transfer key and snapshot identity required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("glivela: invalid transfer key")
	}
	return cipher.NewGCMWithRandomNonce(block)
}
