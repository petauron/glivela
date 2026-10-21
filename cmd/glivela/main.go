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
	"strings"
	"syscall"
	"time"

	"github.com/petauron/glivela/control"
)

type configuration struct {
	Mode                     string                  `json:"mode"`
	Installation             string                  `json:"installation,omitempty"`
	Service                  string                  `json:"service,omitempty"`
	Directory                string                  `json:"directory"`
	Certificate              string                  `json:"certificate"`
	Key                      string                  `json:"key"`
	CA                       string                  `json:"ca"`
	Listen                   string                  `json:"listen,omitempty"`
	SubscriptionsListen      string                  `json:"subscriptionsListen,omitempty"`
	PublicSubscriptionOrigin string                  `json:"publicSubscriptionOrigin,omitempty"`
	Controller               string                  `json:"controller,omitempty"`
	Administrators           []string                `json:"administrators,omitempty"`
	BusinessKey              string                  `json:"businessKey,omitempty"`
	ManagementUI             bool                    `json:"managementUI,omitempty"`
	Xray                     control.SystemdDriver   `json:"xray,omitempty"`
	Entry                    *control.EntryContainer `json:"-"`
	EntryScope               string                  `json:"entryScope,omitempty"`
	EntryProvision           bool                    `json:"entryProvision,omitempty"`
	LegacyEntryCheckpoint    string                  `json:"legacyEntryCheckpoint,omitempty"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "restore-controller-backup" {
		if err := restoreControllerCommand(os.Args[2:], os.Stdout); err != nil {
			log.Print("Glivela controller restore not confirmed; live state unchanged, retain partial destination for inspection")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "stage-native-entry" {
		if err := stageNativeEntryCommand(context.Background(), os.Args[2:], os.Stdout); err != nil {
			log.Print("Glivela native entry staging not confirmed; keep source and recovery state unchanged")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "retire-node" {
		if err := retireNodeCommand(context.Background(), os.Args[2:], os.Stdout); err != nil {
			log.Print("Glivela native retirement not confirmed; do not uninstall")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "activate-controller" {
		if err := activateControllerCommand(os.Args[2:], os.Stdout); err != nil {
			log.Print("Glivela controller activation not confirmed; existing data retained")
			os.Exit(1)
		}
		return
	}
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
	return readConfigurationMode(path, false)
}

func readMaintenanceConfiguration(path string) (configuration, error) {
	return readConfigurationMode(path, true)
}

func readConfigurationMode(path string, maintenance bool) (configuration, error) {
	var cfg configuration
	if maintenance && (!filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/run" || strings.HasPrefix(path, "/run/") || path == "/var/run" || strings.HasPrefix(path, "/var/run/")) {
		return cfg, errors.New("offline maintenance requires the persistent bootstrap, not a runtime copy")
	}
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
	if (cfg.Installation == "") != (cfg.Service == "") || cfg.Mode == "verifier" && cfg.Installation != "" {
		return cfg, errors.New("complete local installation identity required")
	}
	if cfg.Mode == "controller" && cfg.Installation != "" {
		return cfg, errors.New("controller uses its retained container bootstrap, not a native service installation")
	}
	if maintenance && cfg.Installation != "" {
		source, credentials, prefix, err := control.InstalledMaintenanceFiles(cfg.Installation, cfg.Service)
		if err != nil || source != path {
			return cfg, errors.New("persistent bootstrap ownership not confirmed")
		}
		for _, value := range []*string{&cfg.Certificate, &cfg.Key, &cfg.CA, &cfg.EntryScope} {
			if !strings.HasPrefix(*value, prefix) {
				continue
			}
			name := strings.TrimPrefix(*value, prefix)
			path, found := credentials[name]
			if !found {
				return cfg, errors.New("persistent credential ownership not confirmed")
			}
			*value = path
		}
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
	if cfg.Mode != "controller" && cfg.PublicSubscriptionOrigin != "" {
		return cfg, errors.New("published subscription origin belongs to the controller only")
	}
	if cfg.Xray.Role != "" && cfg.Xray.Role != "entry" && cfg.Xray.Role != "landing" {
		return cfg, errors.New("unknown native Xray role")
	}
	if !maintenance && cfg.Mode == "node" && (cfg.Entry != nil || cfg.EntryProvision || cfg.LegacyEntryCheckpoint != "") {
		return cfg, errors.New("Docker entry bootstrap requires explicit offline native handover; no runtime fallback is available")
	}
	return cfg, nil
}

func run(ctx context.Context, path string) error {
	cfg, err := readConfiguration(path)
	if err != nil {
		return err
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
		cfg.Xray, err = resolveNodeDriver(cfg.Xray)
		if err != nil {
			return err
		}
		var driver control.Driver = cfg.Xray
		if cfg.Xray.Role == "entry" {
			entry := &control.NativeEntryDriver{SystemdDriver: cfg.Xray, Directory: cfg.Directory}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if entry.Close(cleanup) != nil {
					log.Print("Glivela entry gate shutdown requires investigation")
				}
			}()
			driver = entry
		}
		nodeRuntime := &control.NativeRuntime{Directory: cfg.Directory, Driver: driver}
		client, err := control.NewClient(cfg.Controller, identity, roots)
		if err != nil {
			return err
		}
		defer client.Close()
		recovery, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = nodeRuntime.Recover(recovery)
		cancel()
		if err != nil {
			return err
		}
		nodeRunner := control.NodeRunner{Client: client, Runtime: nodeRuntime}
		if cfg.Xray.Role == "entry" {
			return runEntryReconcilers(ctx, nodeRunner, control.RouteRunner{Client: client})
		}
		return nodeRunner.Run(ctx, 10*time.Second, func(err error) {
			if err != nil {
				log.Print("Glivela reconciliation did not complete; existing state retained")
			}
		})
	}
	cfg.Listen, err = privateControllerAddress(cfg.Listen)
	if err != nil {
		return err
	}
	if cfg.SubscriptionsListen != "" {
		cfg.SubscriptionsListen, err = privateControllerAddress(cfg.SubscriptionsListen)
		if err != nil {
			return err
		}
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
	if err := store.ConfigureSubscriptionOrigin(cfg.PublicSubscriptionOrigin); err != nil {
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
	backups, stopBackups := context.WithCancel(ctx)
	backupsDone := make(chan struct{})
	defer func() { stopBackups(); <-backupsDone }()
	go func() {
		defer close(backupsDone)
		store.RunControllerBackups(backups, func(error) { log.Print("Glivela controller backup not confirmed; inspect retained recovery snapshots") })
	}()
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
	// Entry health leases are short-lived. Report independently of the slower
	// route verification loop so valid evidence reaches subscription readers
	// before its original deadline; never extend the runtime's lease here.
	go func() { finished <- node.Run(ctx, 2*time.Second, report) }()
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
