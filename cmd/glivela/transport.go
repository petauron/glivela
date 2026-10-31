package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/petauron/glivela/control"
)

func prepareTransportCommand(parent context.Context, args []string, output io.Writer) error {
	return transportCommand(parent, args, output, "prepare")
}

func transportCommand(parent context.Context, args []string, output io.Writer, action string) error {
	flags := flag.NewFlagSet("prepare-private-transport", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "persistent owned node bootstrap")
	offline := flags.Bool("offline-recovery", false, "complete/cancel only after manager crash")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || os.Geteuid() != 0 {
		return errors.New("transport maintenance requires root and persistent bootstrap")
	}
	cfg, err := readMaintenanceConfiguration(*path)
	if err != nil {
		return err
	}
	if cfg.Mode != "node" || cfg.Installation == "" || cfg.Xray.Role != "entry" || cfg.Entry != nil || cfg.EntryProvision || cfg.LegacyEntryCheckpoint != "" {
		return errors.New("installed native entry required")
	}
	if *offline && action == "prepare" {
		return errors.New("preparation requires the live manager")
	}
	if !*offline {
		if err := requestLiveMaintenance(parent, cfg.Directory, action); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]string{"status": "live-maintenance-confirmed", "action": action})
	}
	// Offline completion/cancellation is retained for crash recovery only.
	// Preparation must never stop a healthy manager and its live route gates.
	unlock, err := control.LockDirectory(cfg.Directory)
	if err != nil {
		return err
	}
	defer unlock()
	installed, err := resolveNodeDriver(cfg.Xray)
	if err != nil {
		return err
	}
	keyInfo, err := os.Lstat(cfg.Key)
	if err != nil || !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0077 != 0 {
		return errors.New("private identity required")
	}
	identity, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.Key)
	if err != nil {
		return errors.New("node identity unavailable")
	}
	pem, err := os.ReadFile(cfg.CA)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		return errors.New("node trust unavailable")
	}
	client, err := control.NewClient(cfg.Controller, identity, roots)
	if err != nil {
		return err
	}
	defer client.Close()
	timeout := time.Minute
	if action == "prepare" {
		// The bundled core keeps idle DoH connections for five minutes.
		// Wait for natural drainage before sampling; final-tail freshness
		// remains independently limited to one minute by the runtime.
		timeout = 6 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	driver := &control.NativeEntryDriver{SystemdDriver: installed, Directory: cfg.Directory}
	runtime := &control.NativeRuntime{Directory: cfg.Directory, Driver: driver}
	if action == "cancel" {
		if err := runtime.CancelTransport(ctx, client); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]string{"status": "preparation-cancelled-original-configuration-restored"})
	}
	if action == "complete" {
		if err := runtime.CompleteTransport(ctx, client); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]string{"status": "transport-applied-and-accounting-acknowledged"})
	}
	tail, err := runtime.PrepareTransportTail(ctx)
	if err != nil {
		return err
	}
	// The durable checkpoint remains on disk even if the response is lost.
	// Retrying the command resends it, never invents zero or restarts the core.
	if err := client.RecordTransportTail(ctx, tail); err != nil {
		return err
	}
	if err := runtime.StopPreparedTransport(ctx); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]string{"status": "final-counters-committed-worker-stopped"})
}
