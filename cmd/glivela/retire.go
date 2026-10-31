package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/petauron/glivela/control"
)

func retireNodeCommand(parent context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("retire-node", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "persistent owned node bootstrap")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || os.Geteuid() != 0 {
		return errors.New("native retirement requires root and persistent node bootstrap")
	}
	cfg, err := readMaintenanceConfiguration(*path)
	if err != nil {
		return err
	}
	if cfg.Mode != "node" || cfg.Installation == "" || cfg.Entry != nil || cfg.EntryProvision || cfg.LegacyEntryCheckpoint != "" {
		return errors.New("native installed node required for retirement")
	}
	unlock, err := control.LockDirectory(cfg.Directory)
	if err != nil {
		return err
	}
	defer unlock()
	installed, err := resolveNodeDriver(cfg.Xray)
	if err != nil {
		return err
	}
	var driver control.Driver = installed
	if installed.Role == "entry" {
		driver = &control.NativeEntryDriver{SystemdDriver: installed, Directory: cfg.Directory}
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if err := (&control.NativeRuntime{Directory: cfg.Directory, Driver: driver}).Retire(ctx); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{Status: "native-retired-stop-and-firewall-cleanup-confirmed"})
}
