// Glivela owns node communication; the installer only supplies bootstrap files.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/petauron/glivela/control"
)

type configuration struct {
	Mode                  string                  `json:"mode"`
	Directory             string                  `json:"directory"`
	Certificate           string                  `json:"certificate"`
	Key                   string                  `json:"key"`
	CA                    string                  `json:"ca"`
	Listen                string                  `json:"listen,omitempty"`
	SubscriptionsListen   string                  `json:"subscriptionsListen,omitempty"`
	Controller            string                  `json:"controller,omitempty"`
	Administrators        []string                `json:"administrators,omitempty"`
	BusinessKey           string                  `json:"businessKey,omitempty"`
	ManagementUI          bool                    `json:"managementUI,omitempty"`
	Xray                  control.SystemdDriver   `json:"xray,omitempty"`
	Entry                 *control.EntryContainer `json:"-"`
	EntryScope            string                  `json:"entryScope,omitempty"`
	EntryProvision        bool                    `json:"entryProvision,omitempty"`
	LegacyEntryCheckpoint string                  `json:"legacyEntryCheckpoint,omitempty"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "enroll-nodes" {
		if err := enrollNodesCommand(os.Args[2:], os.Stdout); err != nil {
			log.Print("Glivela enrollment not confirmed; retained state requires inspection")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "retire-entry" {
		if err := retireEntryCommand(context.Background(), os.Args[2:], os.Stdout); err != nil {
			log.Print("Glivela entry retirement not confirmed; do not uninstall")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "backup-legacy-entry" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := backupEntryCommand(ctx, os.Args[2:], os.Stdout); err != nil {
			log.Print("Glivela entry backup failed; source state unchanged")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "provision-entry" {
		if err := provisionEntryCommand(context.Background(), os.Args[2:], os.Stdout); err != nil {
			log.Print("Glivela entry provisioning failed; retained resources require inspection")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "switch-legacy-landing" {
		if err := switchLandingCommand(context.Background(), os.Args[2:], os.Stdout); err != nil {
			log.Print("Glivela first cutover did not complete; inspect retained local recovery state")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "backup-legacy-landing" {
		if err := backupLandingCommand(os.Args[2:], os.Stdout, backupLegacyLanding); err != nil {
			log.Print("Glivela legacy backup failed; no authority or service changes performed")
			os.Exit(1)
		}
		return
	}
	path := flag.String("config", "", "private bootstrap configuration")
	probePath := flag.String("verify-route", "", "entry-side route acceptance request file")
	flag.Parse()
	if *probePath != "" {
		if *path != "" || verifyRoute(context.Background(), *probePath, os.Stdout) != nil {
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *path); err != nil && !errors.Is(err, context.Canceled) {
		log.Print("Glivela startup or shutdown failed; verify local configuration and state")
		os.Exit(1)
	}
}

func readConfiguration(path string) (configuration, error) {
	var cfg configuration
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8<<20 {
		return cfg, errors.New("invalid bootstrap file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil {
		return cfg, errors.New("invalid bootstrap configuration")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || cfg.Mode != "controller" && cfg.Mode != "node" && cfg.Mode != "verifier" {
		return cfg, errors.New("invalid bootstrap mode")
	}
	if cfg.EntryScope != "" {
		if cfg.Mode != "node" || !filepath.IsAbs(cfg.EntryScope) || filepath.Clean(cfg.EntryScope) != cfg.EntryScope {
			return cfg, errors.New("entry scope requires a private local node credential")
		}
		info, err := os.Lstat(cfg.EntryScope)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128<<10 {
			return cfg, errors.New("invalid private entry scope")
		}
		raw, err := os.ReadFile(cfg.EntryScope)
		if err != nil {
			return cfg, err
		}
		entry := &control.EntryContainer{}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(entry) != nil || decoder.Decode(&extra) != io.EOF {
			return cfg, errors.New("invalid entry scope contents")
		}
		if entry.ContainerID != "" || entry.ImageID != "" || entry.ConfigurationDirectory != "" {
			return cfg, errors.New("entry scope cannot select container IDs or host mounts")
		}
		entry.ConfigurationDirectory = filepath.Join(filepath.Dir(cfg.Directory), "entry-config")
		cfg.Entry = entry
	}
	if cfg.Mode != "controller" && cfg.BusinessKey != "" {
		return cfg, errors.New("only controller may load business data")
	}
	if cfg.Mode != "controller" && cfg.ManagementUI {
		return cfg, errors.New("only the controller may serve the management UI")
	}
	if cfg.Entry != nil && (cfg.Mode != "node" || cfg.Xray != (control.SystemdDriver{})) {
		return cfg, errors.New("entry bootstrap requires one local entry driver only")
	}
	if (cfg.EntryProvision || cfg.LegacyEntryCheckpoint != "") && (cfg.Mode != "node" || cfg.Entry == nil) {
		return cfg, errors.New("entry provisioning requires explicit node role")
	}
	if cfg.LegacyEntryCheckpoint != "" && (!filepath.IsAbs(cfg.LegacyEntryCheckpoint) || filepath.Clean(cfg.LegacyEntryCheckpoint) != cfg.LegacyEntryCheckpoint || filepath.Base(cfg.LegacyEntryCheckpoint) != "snapshot.json") {
		return cfg, errors.New("invalid legacy entry checkpoint path")
	}
	if cfg.SubscriptionsListen != "" && (cfg.Mode != "controller" || cfg.BusinessKey == "" || cfg.SubscriptionsListen == cfg.Listen) {
		return cfg, errors.New("only a controller with business storage may publish a separate private subscription origin")
	}
	return cfg, nil
}

func run(ctx context.Context, path string) error {
	cfg, err := readConfiguration(path)
	if err != nil {
		return err
	}
	if cfg.Mode == "node" && cfg.Entry != nil {
		if err := control.PrepareEntryDirectories(*cfg.Entry, cfg.Directory); err != nil {
			return err
		}
	}
	unlock, err := control.LockDirectory(cfg.Directory)
	if err != nil {
		return err
	}
	defer unlock()
	keyInfo, err := os.Lstat(cfg.Key)
	if err != nil || !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0077 != 0 {
		return errors.New("private key permissions invalid")
	}
	identity, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.Key)
	if err != nil {
		return errors.New("invalid TLS identity")
	}
	pem, err := os.ReadFile(cfg.CA)
	if err != nil {
		return errors.New("cannot load CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid CA")
	}
	if cfg.Mode == "verifier" {
		if len(cfg.Administrators) != 0 || cfg.Listen != "" || cfg.Xray != (control.SystemdDriver{}) {
			return errors.New("verifier cannot enroll peers or listen")
		}
		client, err := control.NewClient(cfg.Controller, identity, roots)
		if err != nil {
			return err
		}
		defer client.Close()
		return (control.RouteRunner{Client: client}).Run(ctx, 10*time.Second, func(err error) {
			if err != nil {
				log.Print("Glivela route verification did not complete")
			}
		})
	}
	if cfg.Mode == "node" {
		if len(cfg.Administrators) != 0 || cfg.Listen != "" {
			return errors.New("node cannot enroll peers or listen")
		}
		// The native installer extracts both executables from the same verified
		// application bundle. Derive its directory from this running executable,
		// never from bootstrap data or a guessed host installation layout.
		var nodeRuntime control.Runtime
		var recoverRuntime func(context.Context) error
		if cfg.Entry != nil {
			distribution, resolveErr := runningDistribution()
			if resolveErr != nil {
				return resolveErr
			}
			entry := &control.EntryRuntime{Template: *cfg.Entry, Directory: cfg.Directory, Distribution: distribution, AllowProvision: cfg.EntryProvision, LegacyCheckpoint: cfg.LegacyEntryCheckpoint}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if entry.Close(cleanup) != nil {
					log.Print("Glivela entry gate shutdown requires investigation")
				}
			}()
			nodeRuntime, recoverRuntime = entry, entry.Recover
		} else {
			cfg.Xray, err = resolveNodeDriver(cfg.Xray)
			runtime := &control.NativeRuntime{Directory: cfg.Directory, Driver: cfg.Xray}
			nodeRuntime, recoverRuntime = runtime, runtime.Recover
		}
		if err != nil {
			return err
		}
		client, err := control.NewClient(cfg.Controller, identity, roots)
		if err != nil {
			return err
		}
		defer client.Close()
		recovery, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = recoverRuntime(recovery)
		cancel()
		if err != nil {
			return err
		}
		nodeRunner := control.NodeRunner{Client: client, Runtime: nodeRuntime}
		if cfg.Entry != nil {
			return runEntryReconcilers(ctx, nodeRunner, control.RouteRunner{Client: client})
		}
		return nodeRunner.Run(ctx, 10*time.Second, func(err error) {
			if err != nil {
				log.Print("Glivela reconciliation did not complete; existing state retained")
			}
		})
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return errors.New("invalid control address")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !(ip.IsPrivate() || ip.IsLoopback() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip)) {
		return errors.New("control endpoint must bind a private IP")
	}
	store, err := control.OpenStore(filepath.Join(cfg.Directory, "nodes.json"))
	if err != nil {
		return err
	}
	if err := store.LoadBusiness(cfg.BusinessKey); err != nil {
		return err
	}
	if cfg.ManagementUI {
		distribution, err := runningDistribution()
		if err != nil {
			return err
		}
		if err := store.LoadManagementUI(distribution); err != nil {
			return err
		}
	}
	server, err := control.NewServer(cfg.Listen, store, identity, roots, cfg.Administrators)
	if err != nil {
		return err
	}
	var subscriptions *http.Server
	if cfg.SubscriptionsListen != "" {
		subscriptions, err = control.NewSubscriptionServer(cfg.SubscriptionsListen, store)
		if err != nil {
			return err
		}
	}
	return serveController(ctx, server, subscriptions)
}

// Entry-owned configuration and end-to-end checks use the same authenticated
// identity but independent bounded loops. Neither calls a Vastora task API.
func runEntryReconcilers(parent context.Context, node control.NodeRunner, routes control.RouteRunner) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	finished := make(chan error, 2)
	report := func(err error) {
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Print("Glivela entry reconciliation unverified; existing policy retained")
		}
	}
	go func() { finished <- node.Run(ctx, 10*time.Second, report) }()
	go func() { finished <- routes.Run(ctx, 10*time.Second, report) }()
	err := <-finished
	cancel()
	<-finished
	return err
}

func serveController(ctx context.Context, server, subscriptions *http.Server) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	servers := []*http.Server{server}
	if subscriptions != nil {
		servers = append(servers, subscriptions)
	}
	finished := make(chan error, len(servers))
	go func() { finished <- server.ListenAndServeTLS("", "") }()
	if subscriptions != nil {
		go func() { finished <- subscriptions.ListenAndServe() }()
	}
	var result error
	select {
	case result = <-finished:
	case <-ctx.Done():
		result = ctx.Err()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdown); err != nil {
			_ = s.Close()
			result = errors.Join(result, err)
		}
	}
	return result
}

func resolveNodeDriver(driver control.SystemdDriver) (control.SystemdDriver, error) {
	distribution, err := runningDistribution()
	if err != nil {
		return control.SystemdDriver{}, err
	}
	driver.Distribution = distribution
	return driver.ResolveInstallation()
}

func runningDistribution() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", err
	}
	return filepath.Dir(executable), nil
}
