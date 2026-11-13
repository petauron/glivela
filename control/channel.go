package control

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	pb "github.com/petauron/glivela/internal/controlpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const maxMessage = 8 << 20

// NewServer supplies bounded HTTP handling for the direct node endpoint.
// ListenAndServeTLS must be used; TLS certificates are supplied in the config.
func NewServer(address string, store *Store, certificate tls.Certificate, clients *x509.CertPool, administrators []string) (*http.Server, error) {
	handler, err := controllerHandler(store, administrators)
	if err != nil {
		return nil, err
	}
	configuration, err := ServerTLS(certificate, clients)
	if err != nil {
		return nil, err
	}
	return &http.Server{Addr: address, Handler: newControlHTTP(store, handler), TLSConfig: configuration,
		HTTP2:             &http.HTTP2Config{SendPingTimeout: time.Minute, PingTimeout: 20 * time.Second, WriteByteTimeout: 10 * time.Second},
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
	Exchange(context.Context, string, *Observation) (Desired, error)
}

type exchange struct {
	Receipt *Observation `json:"receipt,omitempty"`
}

// Handler has no admin endpoints. Enrollment and desired state updates are
// separate local administrative operations, never permissions held by nodes.
func Handler(repository Repository) http.Handler {
	// Node operations are served only by the authenticated gRPC service.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "node operation requires gRPC", http.StatusNotFound)
	})
}

// ServerTLS requires both CA validation and explicit enrollment in Repository.
func ServerTLS(certificate tls.Certificate, clients *x509.CertPool) (*tls.Config, error) {
	if clients == nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("control: server identity and client CA required")
	}
	return &tls.Config{NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients}, nil
}

type Client struct {
	endpoint                                                      string
	grpc                                                          *grpc.ClientConn
	http                                                          *http.Client
	desiredWake, routeWake, latencyWake, networkWake, qualityWake chan struct{}
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
	dialer, err := privateNetworkDialer(u.Hostname())
	if err != nil {
		return nil, err
	}
	options := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(transport.TLSClientConfig.Clone())), grpc.WithNoProxy(), grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Minute, Timeout: 20 * time.Second}), grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.DefaultConfig, MinConnectTimeout: 5 * time.Second}), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessage+4096), grpc.MaxCallSendMsgSize(maxMessage+4096))}
	target := "dns:///" + u.Host
	if dialer != nil {
		target = "passthrough:///" + u.Host
		transport.DialContext = dialer.DialContext
		options = append(options, grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		}))
	}
	conn, err := grpc.NewClient(target, options...)
	if err != nil {
		return nil, err
	}
	return &Client{endpoint: u.String(), grpc: conn, http: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control: redirects forbidden") }}, desiredWake: make(chan struct{}, 1), routeWake: make(chan struct{}, 1), latencyWake: make(chan struct{}, 1), networkWake: make(chan struct{}, 1), qualityWake: make(chan struct{}, 1)}, nil
}

func (c *Client) Close() {
	c.http.CloseIdleConnections()
	if c.grpc != nil {
		_ = c.grpc.Close()
	}
}

// currentDesired uses the same node mTLS identity without sending an observation.
func (c *Client) currentDesired(ctx context.Context) (Desired, error) {
	var desired Desired
	err := c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).CurrentDesired, struct{}{}, &desired, 4096, maxMessage)
	if err != nil || desired.Validate() != nil {
		return Desired{}, errors.New("control: desired state unavailable")
	}
	return desired, nil
}
func (c *Client) Exchange(ctx context.Context, receipt *Observation) (Desired, error) {
	var desired Desired
	err := c.nodeCall(ctx, pb.NewNodeOperationsClient(c.grpc).Exchange, exchange{Receipt: receipt}, &desired, maxMessage, maxMessage)
	if err != nil || desired.Validate() != nil {
		return Desired{}, errors.New("control: exchange unavailable")
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
