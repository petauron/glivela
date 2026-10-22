package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"github.com/petauron/glivela/control"
	"io"
	"os"
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
	cfg, err := readMaintenanceConfiguration(*path)
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

func completeLandingCommand(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("complete-legacy-landing", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "existing private node bootstrap file")
	snapshot := flags.String("snapshot-id", "", "controller route-check snapshot identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *snapshot == "" {
		return errors.New("complete landing acceptance options required")
	}
	cfg, err := readMaintenanceConfiguration(*path)
	if err != nil {
		return err
	}
	if cfg.Mode != "node" || cfg.Listen != "" || len(cfg.Administrators) != 0 {
		return errors.New("landing node configuration required")
	}
	driver, err := resolveNodeDriver(cfg.Xray)
	if err != nil {
		return err
	}
	identity, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.Key)
	if err != nil {
		return errors.New("invalid node TLS identity")
	}
	pem, err := os.ReadFile(cfg.CA)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid node CA")
	}
	client, err := control.NewClient(cfg.Controller, identity, roots)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := control.CompleteLegacyLanding(ctx, cfg.Directory, *snapshot, driver, client); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{Status: "accepted"})
}
