package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/petauron/glivela/control"
)

// The installer may stage a transport-only controller before the old writer
// is frozen. After offline adoption, Glivela itself enables owned business and
// the separate subscription origin. This is not a platform configure task.
func activateControllerCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("activate-controller", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "private installed controller bootstrap")
	key := flags.String("storage-key", "", "independent private adopted storage key file")
	subscriptions := flags.String("subscriptions-listen", "", "private subscription origin address")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || *key == "" || *subscriptions == "" {
		return errors.New("controller configuration, storage key file and private subscription origin required")
	}
	cfg, err := readMaintenanceConfiguration(*path)
	if err != nil || cfg.Mode != "controller" || cfg.Listen == *subscriptions {
		return errors.New("installed controller configuration required")
	}
	original, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	unlock, err := control.LockDirectory(cfg.Directory)
	if err != nil {
		return err
	}
	defer unlock()
	store, err := control.OpenStore(filepath.Join(cfg.Directory, "nodes.json"))
	if err != nil {
		return err
	}
	if err := store.LoadBusiness(*key); err != nil {
		return err
	}
	if store.Business().State != "owned-unverified" {
		return errors.New("control: complete offline business adoption before activation")
	}
	if _, err := control.NewSubscriptionServer(*subscriptions, store); err != nil {
		return err
	}
	cfg.BusinessKey, cfg.SubscriptionsListen = *key, *subscriptions
	if err := savePrivateConfiguration(*path, original, cfg); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Status string `json:"status"`
	}{"controller-configured-start-and-route-verification-required"})
}
