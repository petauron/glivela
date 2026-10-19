package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/petauron/glivela/control"
)

func retireEntryCommand(parent context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("retire-entry", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "private entry node journal directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" {
		return errors.New("entry retirement requires its private node directory")
	}
	distribution, err := runningDistribution()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if err := control.RetireEntry(ctx, *directory, distribution); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{Status: "entry-retired-stop-confirmed"})
}

// Provisioning is local/offline, not an administrator or node-channel command.
// No arbitrary image, host script or container operation is accepted remotely.
func provisionEntryCommand(parent context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("provision-entry", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bootstrap := flags.String("config", "", "private node bootstrap")
	desiredPath := flags.String("desired", "", "private controller-produced entry desired state")
	checkpoint := flags.String("legacy-checkpoint", "", "optional frozen legacy entry backup for first handover")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *bootstrap == "" || *desiredPath == "" {
		return errors.New("entry bootstrap and desired file required")
	}
	cfg, err := readConfiguration(*bootstrap)
	if err != nil || cfg.Mode != "node" || cfg.Entry == nil || cfg.Entry.ContainerID != "" || cfg.Entry.ImageID != "" {
		return errors.New("entry provisioning requires an uninitialized local entry bootstrap")
	}
	original, err := os.ReadFile(*bootstrap)
	if err != nil {
		return err
	}
	info, err := os.Lstat(*desiredPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8<<20 {
		return errors.New("private entry desired file required")
	}
	raw, err := os.ReadFile(*desiredPath)
	if err != nil {
		return err
	}
	var desired control.Desired
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&desired) != nil || decoder.Decode(&extra) != io.EOF || desired.Validate() != nil || desired.Entry == nil {
		return errors.New("invalid entry desired file")
	}
	distribution, err := runningDistribution()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	var container control.EntryContainer
	if *checkpoint != "" {
		container, err = control.AdoptLegacyEntry(ctx, *checkpoint, *cfg.Entry, cfg.Directory, distribution, desired)
	} else {
		container, err = control.ProvisionEntry(ctx, *cfg.Entry, cfg.Directory, distribution, desired)
	}
	if err != nil {
		return err
	}
	cfg.Entry = &container
	if *checkpoint != "" {
		cfg.LegacyEntryCheckpoint = *checkpoint
	}
	replacement, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	current, err := os.ReadFile(*bootstrap)
	if err != nil || !bytes.Equal(current, original) {
		return errors.New("node bootstrap changed during provisioning; resource record retained")
	}
	file, err := os.CreateTemp(filepath.Dir(*bootstrap), ".glivela-bootstrap-")
	if err != nil {
		return err
	}
	defer file.Close()
	defer os.Remove(file.Name())
	if _, err := file.Write(replacement); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), *bootstrap); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(*bootstrap))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{Status: "entry-provisioned-awaiting-route-verification"})
}

func backupEntryCommand(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("backup-legacy-entry", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "private root-owned backup directory")
	container := flags.String("container", "", "exact legacy container ID")
	application := flags.String("application", "", "original application identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *container == "" || *application == "" {
		return errors.New("entry backup requires directory, container and application")
	}
	checkpoint, err := control.BackupLegacyEntry(ctx, *directory, *container, *application)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Checkpoint string `json:"checkpoint"`
	}{Checkpoint: checkpoint})
}
