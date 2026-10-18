package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	glivela "github.com/petauron/glivela"
)

const maxMessage = 8 << 20

// NewServer supplies bounded HTTP handling for the direct node endpoint.
// ListenAndServeTLS must be used; TLS certificates are supplied in the config.
func NewServer(address string, repository Repository, certificate tls.Certificate, clients *x509.CertPool) (*http.Server, error) {
	if repository == nil {
		return nil, errors.New("control: repository required")
	}
	configuration, err := ServerTLS(certificate, clients)
	if err != nil {
		return nil, err
	}
	return &http.Server{Addr: address, Handler: Handler(repository), TLSConfig: configuration,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}, nil
}

// CertificateID binds authorization to the exact enrolled leaf certificate,
// not to a caller-controlled node ID or an ambiguous common name.
func CertificateID(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(digest[:])
}

// Repository is owned by Glivela. Exchange must atomically compare a report
// with the current desired revision before recording it.
type Repository interface {
	Exchange(context.Context, string, *glivela.AppliedReceipt) (Desired, error)
}

type exchange struct {
	Receipt *glivela.AppliedReceipt `json:"receipt,omitempty"`
}

// Handler has no admin endpoints. Enrollment and desired state updates are
// separate local administrative operations, never permissions held by nodes.
func Handler(repository Repository) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client authentication required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/exchange" || r.URL.RawQuery != "" {
			http.Error(w, "unsupported request", http.StatusNotFound)
			return
		}
		var request exchange
		if decode(http.MaxBytesReader(w, r.Body, maxMessage), &request) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		desired, err := repository.Exchange(r.Context(), CertificateID(r.TLS.PeerCertificates[0]), request.Receipt)
		if err != nil {
			// Never expose node inventory, configuration or storage errors.
			http.Error(w, "exchange refused", http.StatusForbidden)
			return
		}
		if desired.Validate() != nil {
			http.Error(w, "desired state unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(desired)
	})
}

// ServerTLS requires both CA validation and explicit enrollment in Repository.
func ServerTLS(certificate tls.Certificate, clients *x509.CertPool) (*tls.Config, error) {
	if clients == nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("control: server identity and client CA required")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients}, nil
}

type Client struct {
	endpoint string
	http     *http.Client
}

func NewClient(endpoint string, identity tls.Certificate, roots *x509.CertPool) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || roots == nil || len(identity.Certificate) == 0 {
		return nil, errors.New("control: HTTPS endpoint, identity and CA required")
	}
	u.Path = "/v1/exchange"
	transport := &http.Transport{
		// Intentionally no ProxyFromEnvironment: node control traffic must not
		// inherit a system proxy or route through the proxy being configured.
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{identity}},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConnsPerHost: 1, IdleConnTimeout: time.Minute,
	}
	return &Client{endpoint: u.String(), http: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control: redirects forbidden") }}}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) Exchange(ctx context.Context, receipt *glivela.AppliedReceipt) (Desired, error) {
	raw, err := json.Marshal(exchange{Receipt: receipt})
	if err != nil {
		return Desired{}, errors.New("control: cannot encode report")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(raw))
	if err != nil {
		return Desired{}, errors.New("control: invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return Desired{}, errors.New("control: exchange failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Desired{}, errors.New("control: exchange refused")
	}
	var desired Desired
	if decode(io.LimitReader(response.Body, maxMessage+1), &desired) != nil || desired.Validate() != nil {
		return Desired{}, errors.New("control: invalid desired state")
	}
	return desired, nil
}

func decode(reader io.Reader, value any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("control: trailing data")
	}
	return nil
}
