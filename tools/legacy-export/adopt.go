package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/control"
)

func adoptFinalCommand(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("adopt-final", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	data := flags.String("data-directory", "", "still-stopped old Center data directory")
	backup := flags.String("backup-directory", "", "completed private final capture")
	directory := flags.String("state-directory", "", "offline Glivela controller directory")
	snapshot := flags.String("snapshot", "", "expected staged snapshot identity")
	keyPath := flags.String("storage-key", "", "independent private Glivela storage key file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || os.Geteuid() != 0 {
		return errors.New("root adoption arguments required")
	}
	key, err := privateFile(*keyPath, 32)
	if err != nil || len(key) != 32 {
		return errors.New("private Glivela storage key required")
	}
	defer clear(key)
	return adoptFinal(ctx, *data, *backup, *directory, *snapshot, key, inspectOldContainers)
}

// Data ownership is committed only from the final persisted backup. The
// operator must keep old writers stopped until the boundary migration ends.
// Small unsampled traffic tails are deliberately not reconciled or invented.
func adoptFinal(ctx context.Context, data, backup, directory, snapshot string, key []byte, inspect func(context.Context) ([]oldCenterContainer, error)) error {
	invalid := errors.New("final snapshot or stopped-writer evidence differs")
	if pathsOverlap(data, backup) || pathsOverlap(data, directory) || pathsOverlap(backup, directory) {
		return invalid
	}
	raw, err := privateFile(filepath.Join(backup, "capture.json"), 4096)
	if err != nil {
		return err
	}
	var receipt finalCapture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&receipt) != nil || decoder.Decode(&extra) != io.EOF || receipt.Version != 1 || !validContainerID(receipt.ContainerID) {
		return invalid
	}
	digest := sha256.Sum256(raw)
	ownership := glivela.BusinessOwnership{SourceSHA256: receipt.DatabaseSHA256, CaptureSHA256: hex.EncodeToString(digest[:]), PreviousWriterID: receipt.ContainerID, StoppedAt: receipt.StoppedAt, CapturedAt: receipt.CapturedAt}
	if ownership.Validate(receipt.DatabaseSHA256) != nil {
		return invalid
	}
	containers, err := inspect(ctx)
	if err != nil {
		return err
	}
	before, err := stoppedCenter(containers, receipt.ContainerID, data)
	if err != nil || before.State.StartedAt != receipt.StartedAt || before.State.FinishedAt != receipt.StoppedAt {
		return invalid
	}
	verifySource := func() error {
		for _, root := range []string{backup, data} {
			path := filepath.Join(root, "center.db")
			if err := standalone(path); err != nil {
				return err
			}
			database, err := privateFile(path, maxSnapshotBytes)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(database)
			clear(database)
			if hex.EncodeToString(sum[:]) != receipt.DatabaseSHA256 {
				return invalid
			}
		}
		backupKey, err := privateFile(filepath.Join(backup, "center.key"), 32)
		if err != nil {
			return err
		}
		defer clear(backupKey)
		liveKey, err := privateFile(filepath.Join(data, "center.key"), 32)
		if err != nil {
			return err
		}
		defer clear(liveKey)
		if len(backupKey) != 32 || !bytes.Equal(backupKey, liveKey) || bytes.Equal(key, backupKey) {
			return invalid
		}
		return nil
	}
	if err := verifySource(); err != nil {
		return err
	}
	containers, err = inspect(ctx)
	if err != nil {
		return err
	}
	after, err := stoppedCenter(containers, receipt.ContainerID, data)
	if err != nil || after.State.StartedAt != before.State.StartedAt || after.State.FinishedAt != before.State.FinishedAt {
		return invalid
	}
	if err := verifySource(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return control.AdoptStagedBusiness(directory, snapshot, ownership, key)
}
