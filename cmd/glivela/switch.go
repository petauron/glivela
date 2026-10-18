package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/petauron/glivela/control"
	"io"
)

func switchLandingCommand(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("switch-legacy-landing", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "existing private node bootstrap file")
	checkpoint := flags.String("checkpoint", "", "verified recovery snapshot path")
	node := flags.String("node-id", "", "existing node identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *node == "" || *checkpoint == "" {
		return errors.New("invalid first cutover options")
	}
	cfg, err := readConfiguration(*path)
	if err != nil {
		return err
	}
	if cfg.Mode != "node" || cfg.Listen != "" || len(cfg.Administrators) != 0 {
		return errors.New("first cutover requires the existing node configuration")
	}
	driver, err := resolveNodeDriver(cfg.Xray)
	if err != nil {
		return err
	}
	if err := control.SwitchLegacyLanding(ctx, cfg.Directory, *checkpoint, *node, driver); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{Status: "awaiting-routes"})
}
