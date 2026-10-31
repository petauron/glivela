package control

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"time"
)

// ConfigurePanelAccess adds a separate SNI identity on the existing private
// listener. Node trust is unchanged. Only the exact enrolled Center client
// certificate gets management access; its private key is never supplied here.
func ConfigurePanelAccess(server *http.Server, store *Store, administrators []string, path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 24<<10 {
		return errors.New("control: unsafe panel credential file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return errors.New("control: panel credentials unavailable")
	}
	var bundle struct {
		CA                string `json:"ca"`
		Certificate       string `json:"certificate"`
		Key               string `json:"key"`
		ClientCertificate string `json:"clientCertificate"`
	}
	if json.Unmarshal(raw, &bundle) != nil {
		return errors.New("control: invalid panel credentials")
	}
	certificate, err := tls.X509KeyPair([]byte(bundle.Certificate), []byte(bundle.Key))
	if err != nil {
		return errors.New("control: invalid panel server identity")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundle.CA)) {
		return errors.New("control: invalid panel CA")
	}
	block, rest := pem.Decode([]byte(bundle.ClientCertificate))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return errors.New("control: invalid panel client")
	}
	client, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("control: invalid panel client")
	}
	if _, err = client.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now()}); err != nil {
		return errors.New("control: panel client expired or untrusted")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return errors.New("control: invalid panel server")
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "panel.glivela.internal", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("control: panel server expired or untrusted")
	}
	handler, err := controllerHandler(store, append(append([]string{}, administrators...), CertificateID(client)))
	if err != nil {
		return err
	}
	privateTLS := server.TLSConfig.Clone()
	panelTLS := &tls.Config{NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	// Preserve the node listener and its CA, even for clients without SNI.
	server.TLSConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName == "panel.glivela.internal" {
			return panelTLS, nil
		}
		return privateTLS, nil
	}
	server.Handler = newControlHTTP(store, handler)
	return nil
}
