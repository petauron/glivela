package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/petauron/glivela/control"
)

func stageNativeEntryCommand(parent context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("stage-native-entry", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "persistent owned native node bootstrap")
	checkpoint := flags.String("checkpoint", "", "verified private legacy entry snapshot")
	desiredPath := flags.String("desired", "", "private typed desired state from the owned controller")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || *checkpoint == "" || *desiredPath == "" || os.Geteuid() != 0 {
		return errors.New("root native entry staging requires config, checkpoint and desired state")
	}
	cfg, err := readMaintenanceConfiguration(*path)
	if err != nil {
		return err
	}
	if cfg.Mode != "node" || cfg.Installation == "" || cfg.Xray.Role != "entry" || cfg.Entry != nil || cfg.EntryProvision || cfg.LegacyEntryCheckpoint != "" {
		return errors.New("native installed entry configuration required")
	}
	info, err := os.Lstat(*desiredPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 3<<20 {
		return errors.New("private bounded entry desired file required")
	}
	raw, err := os.ReadFile(*desiredPath)
	if err != nil {
		return err
	}
	defer clear(raw)
	var desired control.Desired
	var extra any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&desired) != nil || decoder.Decode(&extra) != io.EOF || desired.Validate() != nil || desired.Entry == nil {
		return errors.New("typed entry desired state required")
	}
	installed, err := resolveNodeDriver(cfg.Xray)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	driver := &control.NativeEntryDriver{SystemdDriver: installed, Directory: cfg.Directory}
	if err := control.StageNativeEntryHandover(ctx, *checkpoint, driver, desired); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{Status: "staged-awaiting-installation-binding-and-runtime-verification"})
}
