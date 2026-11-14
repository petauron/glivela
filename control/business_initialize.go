package control

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
)

// FreshBusiness contains only newly configured topology. Accounts and credentials
// are created through the ordinary management APIs after initialization.
type FreshBusiness struct {
	Endpoints  []glivela.ImportEndpoint `json:"endpoints"`
	References glivela.ImportReferences `json:"references"`
}

// InitializeBusiness is an offline, one-time operation. It never imports a
// legacy archive and never recreates a missing live ledger after an intent exists.
func InitializeBusiness(directory string, topology FreshBusiness, storageKey []byte) error {
	unlock, err := LockDirectory(directory)
	if err != nil {
		return err
	}
	defer unlock()
	if len(storageKey) != 32 {
		return errors.New("control: 256-bit storage key required")
	}
	for _, name := range []string{"business.json", "business.pending.json", "business.adoption.json", "business.nodes.applied.json"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("control: initialization requires a fresh business directory; existing state retained")
		}
	}
	store, err := OpenStore(filepath.Join(directory, "nodes.json"))
	if err != nil {
		return err
	}
	if len(store.nodes) != 0 {
		return errors.New("control: initialize business before enrolling nodes")
	}
	// An initialized topology has no applied observations, consumed traffic or
	// migration binding. Those values must come from actual runtime reporting.
	for _, e := range topology.Endpoints {
		if e.UsedBytes != 0 || e.AppliedRevision != 0 || e.HistoricalHealthy || e.Retired || e.LegacyRetired || e.RuntimeCertificateID != "" || e.RuntimeConfigSHA256 != "" || e.PreviousStatus != "pending" || e.DesiredRevision != 1 {
			return errors.New("control: fresh endpoints must not contain imported runtime state")
		}
	}
	raw, err := json.Marshal(topology)
	if err != nil {
		return err
	}
	defer clear(raw)
	origin := nodeStateHash(raw)
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	snapshot := id.String()
	header, err := json.Marshal(struct {
		Version      int    `json:"version"`
		Origin       string `json:"origin"`
		SnapshotID   string `json:"snapshotId"`
		SourceSHA256 string `json:"sourceSha256"`
	}{1, "native", snapshot, origin})
	if err != nil {
		return err
	}
	plan, err := glivela.PlanImport(nil)
	if err != nil {
		return err
	}
	material := glivela.ImportMaterial{
		ServerTransportVersion: 1,
		SourceSHA256:           origin, RetainedSource: header, Endpoints: topology.Endpoints,
		References: topology.References, Plan: plan,
		SubscriptionTokens: map[string]string{}, ProtocolSecrets: map[string]string{}, HysteriaSecrets: map[string]string{},
		ResetSchedules: map[string]glivela.ImportResetSchedule{}, TrafficCounters: map[string]glivela.ImportTrafficCounters{},
		Ownership: &glivela.BusinessOwnership{Origin: "native", SourceSHA256: origin, CaptureSHA256: origin, CapturedAt: time.Now().UTC().Format(time.RFC3339Nano)},
	}
	sealed, err := glivela.SealImportMaterial(material, storageKey, snapshot)
	if err != nil {
		return err
	}
	checkpoint, err := json.Marshal(stagedImport{Version: 1, SnapshotID: snapshot, Sealed: sealed})
	if err != nil {
		return err
	}
	intent, err := json.Marshal(businessAdoptionIntent{Version: 1, SnapshotID: snapshot, SourceSHA256: origin, CaptureSHA256: origin})
	if err != nil {
		return err
	}
	if err := writeNewBusinessFile(directory, "business.adoption.json", intent); err != nil {
		return err
	}
	return writeNewBusinessFile(directory, "business.json", checkpoint)
}
