// Isolated native-runtime acceptance fixture. Never shipped with Glivela.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/control"
)

const root = "/var/lib/glivela-alpine-acceptance"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func write(name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, name), raw, 0600)
}
func certificate(name string, ca *x509.Certificate, signer *ecdsa.PrivateKey, server bool) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if ca == nil {
		cert.IsCA = true
		cert.BasicConstraintsValid = true
		cert.KeyUsage |= x509.KeyUsageCertSign
		ca = cert
		signer = key
	} else if server {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert.DNSNames = []string{"localhost", "www.example.com", "www.cloudflare.com"}
		cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("93.184.216.34")}
	} else {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	pk, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(root, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(root, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk}), 0600); err != nil {
		return nil, nil, err
	}
	return parsed, key, nil
}
func initialize() error {
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, "state.json")); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	ca, key, err := certificate("ca", nil, nil, false)
	if err != nil {
		return err
	}
	if _, _, err := certificate("server", ca, key, true); err != nil {
		return err
	}
	node, _, err := certificate("node", ca, key, false)
	if err != nil {
		return err
	}
	curve, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	id := uuid.NewString()
	endpoint := glivela.RealityEndpoint{ID: "entry-example-endpoint", EntryID: "entry-example", InboundTag: "entry-example-inbound", ListenAddress: "100.64.0.3", ListenPort: 10443, AdvertiseHost: "entry.example.test", AdvertisePort: 10443, Target: "www.example.com:443", ServerNames: []string{"www.example.com"}, PrivateKey: base64.RawURLEncoding.EncodeToString(curve.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(curve.PublicKey().Bytes()), ShortIDs: []string{"abcd"}, Fingerprint: "chrome"}
	material := glivela.CredentialMaterial{Credential: glivela.Credential{ID: "native-example", AccountID: "account-example", Kind: glivela.NativeCredential, User: "example-user", Identity: glivela.Identity(id), EntryID: "entry-example", Enabled: true}, ProtocolID: id}
	desired, err := control.NewEntryDesired(glivela.XrayPlan{Revision: 1, RealityEndpoints: []glivela.RealityEndpoint{endpoint}, Credentials: []glivela.CredentialMaterial{material}}, control.EntryNetwork{})
	if err != nil {
		return err
	}
	store, err := control.OpenStore(filepath.Join(root, "state.json"))
	if err != nil {
		return err
	}
	if err := store.Put(control.Node{ID: "entry-example", CertificateID: control.CertificateID(node), Desired: desired}); err != nil {
		return err
	}
	secrets := map[string]string{}
	for field, file := range map[string]string{"certificate_pem": "node.pem", "private_key_pem": "node.key", "ca_pem": "ca.pem"} {
		raw, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			return err
		}
		secrets[field] = string(raw)
	}
	if err := write("install-inputs.json", map[string]any{"config": map[string]any{"controller_url": "https://127.0.0.1:16443", "network_interface": "lo", "backend_port": 10443}, "secrets": secrets}); err != nil {
		return err
	}
	client := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{
		map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "100.64.0.3", "port": 10443, "users": []any{map[string]any{"id": id, "encryption": "none", "flow": "xtls-rprx-vision"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": "www.example.com", "fingerprint": "chrome", "password": endpoint.PublicKey, "shortId": "abcd"}, "sockopt": map[string]any{"dialerProxy": "fixture-front"}}},
		map[string]any{"tag": "fixture-front", "protocol": "freedom", "settings": map[string]any{"proxyProtocol": 2, "finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{"100.64.0.3/32"}, "port": "10443"}}}},
	}}
	return write("client.json", client)
}
func run() error {
	marker, err := os.ReadFile("/etc/vastora-isolated-test")
	if err != nil || string(marker) != "alpine-openrc\n" || os.Geteuid() != 0 {
		return errors.New("isolated Alpine fixture marker/root required")
	}
	if len(os.Args) != 2 {
		return errors.New("init, serve, or verify required")
	}
	if err := initialize(); err != nil {
		return err
	}
	if os.Args[1] == "init" {
		fmt.Println("synthetic independent Glivela identity prepared")
		return nil
	}
	if os.Args[1] == "diagnose" || os.Args[1] == "activate" {
		raw, err := os.ReadFile("/run/vastora-pkg-glivela-node/config-node.json")
		if err != nil {
			return err
		}
		var cfg struct {
			Directory string                `json:"directory"`
			Xray      control.SystemdDriver `json:"xray"`
		}
		if json.Unmarshal(raw, &cfg) != nil {
			return errors.New("invalid fixture bootstrap")
		}
		files, err := filepath.Glob("/opt/vastora/packages/*/artifacts/bundle/runtime.json")
		if err != nil || len(files) != 1 {
			return errors.New("one fixture distribution required")
		}
		cfg.Xray.Distribution = filepath.Dir(files[0])
		driver, err := cfg.Xray.ResolveInstallation()
		if err != nil {
			return err
		}
		raw, err = os.ReadFile(filepath.Join(root, "state.json"))
		if err != nil {
			return err
		}
		var nodes []control.Node
		if json.Unmarshal(raw, &nodes) != nil || len(nodes) != 1 {
			return errors.New("one fixture node required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d := &control.NativeEntryDriver{SystemdDriver: driver, Directory: cfg.Directory}
		if os.Args[1] == "activate" {
			return d.Activate(ctx, nodes[0].Desired, nil)
		}
		return d.Healthy(ctx, nodes[0].Desired)
	}
	if os.Args[1] == "verify" {
		raw, err := os.ReadFile(filepath.Join(root, "state.json"))
		if err != nil {
			return err
		}
		var nodes []control.Node
		if json.Unmarshal(raw, &nodes) != nil || len(nodes) != 1 || nodes[0].Receipt == nil || !nodes[0].Receipt.RuntimeReady || time.Since(nodes[0].ReportedAt) > 30*time.Second {
			return errors.New("Glivela runtime has no recent ready receipt")
		}
		fmt.Println("Glivela runtime ready with recent authenticated receipt")
		return nil
	}
	if os.Args[1] != "serve" {
		return errors.New("unknown fixture command")
	}
	ca, err := os.ReadFile(filepath.Join(root, "ca.pem"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("invalid fixture CA")
	}
	identity, err := tls.LoadX509KeyPair(filepath.Join(root, "server.pem"), filepath.Join(root, "server.key"))
	if err != nil {
		return err
	}
	store, err := control.OpenStore(filepath.Join(root, "state.json"))
	if err != nil {
		return err
	}
	server, err := control.NewServer("127.0.0.1:16443", store, identity, pool, nil)
	if err != nil {
		return err
	}
	defer server.Shutdown(context.Background())
	errs := make(chan error, 4)
	for _, listen := range []string{"127.0.0.1:53", "1.1.1.1:53", "1.0.0.1:53"} {
		go func() { errs <- serveDNS(listen) }()
	}
	go func() { errs <- server.ListenAndServeTLS("", "") }()
	return <-errs
}
