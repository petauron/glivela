package control

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	glivela "github.com/petauron/glivela"
)

const controllerBackupLimit = 192 << 20
const controllerBackupContext = "glivela-controller-backup-v1"

// Only controller data is included. The independently held business key and
// installation TLS credentials must remain in their private managed storage.
// The two owned slots bound disk growth; migration/upgrade backups are untouched.
type controllerBackup struct {
	Version   int                        `json:"version"`
	CreatedAt time.Time                  `json:"createdAt"`
	Files     map[string]json.RawMessage `json:"files"`
}

func privateBackupBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > controllerBackupLimit {
		return nil, errors.New("control: unsafe controller backup file")
	}
	return os.ReadFile(path)
}

func controllerBackupCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("control: controller backup key required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func openControllerBackup(raw, key []byte) (controllerBackup, error) {
	var value controllerBackup
	aead, err := controllerBackupCipher(key)
	if err != nil || len(raw) > controllerBackupLimit {
		return value, errors.New("control: invalid controller backup")
	}
	plain, err := aead.Open(nil, nil, raw, []byte(controllerBackupContext))
	if err != nil {
		return value, errors.New("control: controller backup authentication failed")
	}
	defer clear(plain)
	if decode(bytes.NewReader(plain), &value) != nil || value.Version != 1 || value.CreatedAt.IsZero() || value.CreatedAt.After(time.Now().Add(5*time.Minute)) || len(value.Files) != 3 {
		return controllerBackup{}, errors.New("control: invalid controller backup contents")
	}
	for _, name := range []string{"nodes.json", "business.json", "business.adoption.json"} {
		if !json.Valid(value.Files[name]) {
			return controllerBackup{}, errors.New("control: incomplete controller backup")
		}
	}
	return value, nil
}

func (s *Store) BackupController(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.business == nil {
		return nil
	} // Transport-only installations have no owned business data.
	if s.business.faulted || s.business.material.Ownership == nil {
		return errors.New("control: business state requires recovery before backup")
	}
	key, err := readBusinessKey(s.business.keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	directory := filepath.Dir(s.path)
	material, snapshot, err := readOwnedBusiness(directory, key)
	if err != nil || snapshot != s.business.snapshotID || !reflect.DeepEqual(material, s.business.material) {
		return errors.New("control: controller backup source changed")
	}
	value := controllerBackup{Version: 1, CreatedAt: now.UTC(), Files: map[string]json.RawMessage{}}
	for _, name := range []string{"nodes.json", "business.json", "business.adoption.json"} {
		raw, err := privateBackupBytes(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		value.Files[name] = raw
	}
	var nodes []Node
	if json.Unmarshal(value.Files["nodes.json"], &nodes) != nil {
		return errors.New("control: invalid controller node snapshot")
	}
	observed := map[string]Node{}
	for _, node := range nodes {
		observed[node.CertificateID] = node
	}
	expectedNodes, expectedErr := json.Marshal(s.nodes)
	observedNodes, observedErr := json.Marshal(observed)
	if len(observed) != len(nodes) || expectedErr != nil || observedErr != nil || !bytes.Equal(expectedNodes, observedNodes) {
		return errors.New("control: controller node snapshot differs")
	}
	plain, err := json.Marshal(value)
	if err != nil || len(plain) > controllerBackupLimit-64 {
		return errors.New("control: controller backup size limit")
	}
	defer clear(plain)
	aead, err := controllerBackupCipher(key)
	if err != nil {
		return err
	}
	sealed := aead.Seal(nil, nil, plain, []byte(controllerBackupContext))
	name := "controller-backup-" + strconv.FormatInt(now.UTC().Unix()/3600%2, 10) + ".gcm"
	path := filepath.Join(directory, name)
	if _, err := os.Lstat(path); err == nil {
		previous, err := privateBackupBytes(path)
		if err != nil {
			return err
		}
		if _, err := openControllerBackup(previous, key); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := replacePrivate(directory, name, sealed); err != nil {
		return err
	}
	readback, err := privateBackupBytes(path)
	if err != nil || !bytes.Equal(readback, sealed) {
		return errors.New("control: controller backup readback differs")
	}
	if _, err := openControllerBackup(readback, key); err != nil {
		return err
	}
	return nil
}

func (s *Store) RunControllerBackups(ctx context.Context, report func(error)) {
	timer := time.NewTicker(time.Hour)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.BackupController(time.Now()); err != nil && report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// RestoreControllerBackup never overwrites a running controller or changes
// its configured directory. Partial destinations remain private evidence for
// operator review. Activation is a separate, stopped-controller operation.
func RestoreControllerBackup(source, keyPath, destination string) error {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return errors.New("control: new absolute restore directory required")
	}
	parent, err := os.Lstat(filepath.Dir(destination))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0077 != 0 {
		return errors.New("control: private restore parent required")
	}
	for directory := filepath.Dir(destination); directory != "/"; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("control: unsafe restore directory")
		}
	}
	key, err := readBusinessKey(keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	raw, err := privateBackupBytes(source)
	if err != nil {
		return err
	}
	value, err := openControllerBackup(raw, key)
	if err != nil {
		return err
	}
	var staged stagedImport
	if decode(bytes.NewReader(value.Files["business.json"]), &staged) != nil || !glivela.ValidIdentifier(staged.SnapshotID) {
		return errors.New("control: invalid backup business identity")
	}
	if _, err := glivela.OpenImportMaterial(staged.Sealed, key, staged.SnapshotID); err != nil {
		return err
	}
	// Runtime observations are caches, not restored proof of a live process.
	// Retain original evidence in the encrypted snapshot, but require fresh
	// authenticated node/route observations before publishing restored routes.
	var nodes []Node
	if json.Unmarshal(value.Files["nodes.json"], &nodes) != nil {
		return errors.New("control: invalid restored node inventory")
	}
	for i := range nodes {
		nodes[i].Receipt = nil
		nodes[i].ReportedAt = time.Time{}
		nodes[i].EntryHealthBarrierAt = time.Now().UTC()
		// Checks are issued runtime challenges, not configuration or history.
		// An unissued zero timestamp is invalid persisted state; discard the
		// cached challenges so reconciliation issues fresh ones after recovery.
		nodes[i].Checks = nil
	}
	value.Files["nodes.json"], err = json.Marshal(nodes)
	if err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return err
	}
	for _, name := range []string{"business.adoption.json", "business.json", "nodes.json"} {
		if err := writeNewBusinessFile(destination, name, value.Files[name]); err != nil {
			return err
		}
	}
	store, err := OpenStore(filepath.Join(destination, "nodes.json"))
	if err != nil {
		return err
	}
	return store.LoadBusiness(keyPath)
}
