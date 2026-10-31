package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/petauron/glivela/control"
)

func initializeBusinessCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("initialize-business", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "installed private controller bootstrap")
	topologyPath := flags.String("topology", "", "private fresh topology JSON")
	keyPath := flags.String("storage-key", "", "private 32-byte business key file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath == "" || *topologyPath == "" || *keyPath == "" {
		return errors.New("controller configuration, topology and storage key required")
	}
	cfg, err := readMaintenanceConfiguration(*configPath)
	if err != nil || cfg.Mode != "controller" {
		return errors.New("installed controller configuration required")
	}
	readPrivate := func(path string, max int64) ([]byte, error) {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > max {
			return nil, errors.New("private regular input file required")
		}
		return os.ReadFile(path)
	}
	raw, err := readPrivate(*topologyPath, 8<<20)
	if err != nil {
		return err
	}
	defer clear(raw)
	var topology control.FreshBusiness
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&topology) != nil || decoder.Decode(&extra) != io.EOF {
		return errors.New("invalid fresh topology")
	}
	key, err := readPrivate(*keyPath, 32)
	if err != nil {
		return err
	}
	defer clear(key)
	if err := control.InitializeBusiness(cfg.Directory, topology, key); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{"initialized-activate-controller-and-enroll-nodes-required"})
}
