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
	Mode        string                `json:"mode"`
	Directory   string                `json:"directory"`
	Certificate string                `json:"certificate"`
	Key         string                `json:"key"`
	CA          string                `json:"ca"`
	Listen      string                `json:"listen,omitempty"`
	Controller  string                `json:"controller,omitempty"`
	Nodes       []control.Node        `json:"nodes,omitempty"`
	Xray        control.SystemdDriver `json:"xray,omitempty"`
}

func main() {
	path := flag.String("config", "", "private bootstrap configuration")
	importPath := flag.String("stage-accounts", "", "private encrypted account migration package (offline only)")
	importSnapshot := flag.String("snapshot", "", "account migration snapshot identity")
	importDirectory := flag.String("state-directory", "", "private controller state directory for offline import")
	transferKey := flag.String("transfer-key", "", "private raw 32-byte transfer key file")
	storageKey := flag.String("storage-key", "", "private raw 32-byte controller storage key file")
	flag.Parse()
	if *importPath != "" {
		if *path != "" || stageAccounts(*importPath, *importSnapshot, *importDirectory, *transferKey, *storageKey) != nil {
			log.Print("Glivela offline account staging failed; existing state retained")
			os.Exit(1)
		}
		return
	}
	if *importSnapshot != "" || *importDirectory != "" || *transferKey != "" || *storageKey != "" {
		log.Print("Account migration options require -stage-accounts")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *path); err != nil && !errors.Is(err, context.Canceled) {
		log.Print("Glivela startup or shutdown failed; verify local configuration and state")
		os.Exit(1)
	}
}

func run(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8<<20 {
		return errors.New("invalid bootstrap file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg configuration
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil {
		return errors.New("invalid bootstrap configuration")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || cfg.Mode != "controller" && cfg.Mode != "node" {
		return errors.New("invalid bootstrap mode")
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
	if cfg.Mode == "node" {
		if len(cfg.Nodes) != 0 || cfg.Listen != "" {
			return errors.New("node cannot enroll peers or listen")
		}
		cfg.Xray, err = cfg.Xray.ResolveInstallation()
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
	for _, node := range cfg.Nodes {
		if err = store.Put(node); err != nil {
			return err
		}
	}
	server, err := control.NewServer(cfg.Listen, store, identity, roots)
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
