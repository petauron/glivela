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
	Mode           string                `json:"mode"`
	Directory      string                `json:"directory"`
	Certificate    string                `json:"certificate"`
	Key            string                `json:"key"`
	CA             string                `json:"ca"`
	Listen         string                `json:"listen,omitempty"`
	Controller     string                `json:"controller,omitempty"`
	Administrators []string              `json:"administrators,omitempty"`
	BusinessKey    string                `json:"businessKey,omitempty"`
	Xray           control.SystemdDriver `json:"xray,omitempty"`
}

func main() {
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
	if cfg.Mode != "controller" && cfg.BusinessKey != "" {
		return cfg, errors.New("only controller may load business data")
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
		client, err := control.NewClient(cfg.Controller, identity, roots)
		if err != nil {
			return err
		}
		defer client.Close()
		runtime := &control.NativeRuntime{Directory: cfg.Directory, Driver: cfg.Xray}
		recovery, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = runtime.Recover(recovery)
		cancel()
		if err != nil {
			return err
		}
		return (control.NodeRunner{Client: client, Runtime: runtime}).Run(ctx, 10*time.Second, func(err error) {
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
	server, err := control.NewServer(cfg.Listen, store, identity, roots, cfg.Administrators)
	if err != nil {
		return err
	}
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServeTLS("", "") }()
	select {
	case err = <-finished:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = server.Shutdown(shutdown)
		if err != nil {
			_ = server.Close()
			return err
		}
		if serveErr := <-finished; !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return ctx.Err()
	}
}

func resolveNodeDriver(driver control.SystemdDriver) (control.SystemdDriver, error) {
	executable, err := os.Executable()
	if err != nil {
		return control.SystemdDriver{}, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return control.SystemdDriver{}, err
	}
	driver.Distribution = filepath.Dir(executable)
	return driver.ResolveInstallation()
}
