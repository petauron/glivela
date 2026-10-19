//go:build linux

package control

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	glivela "github.com/petauron/glivela"
)

// Called only by the guarded isolated-netns native authentication test. This
// exercises the explicitly configured existing HY2 inbound; no routed UDP or
// public ingress/worker ownership capability is inferred from its result.
func exerciseHysteriaAccountAuthentication(t *testing.T, ctx context.Context, driver SystemdDriver, certificateSource, target *httptest.Server, roots *x509.CertPool, requests *atomic.Int64) {
	t.Helper()
	s, d := hysteriaAccountFixture(t, certificateSource)
	endpoint := d.Entry.HysteriaEndpoints[0]
	first, second := d.Entry.Credentials[0], d.Entry.Credentials[1]
	accountPlan := func(id string) glivela.AccountPlan {
		for _, account := range s.business.material.Plan.Accounts {
			if account.Account.ID == id {
				return account.Account.Plan
			}
		}
		t.Fatal("account missing")
		return glivela.AccountPlan{}
	}
	firstPlan, secondPlan := accountPlan("account-example"), accountPlan("account-other")
	current := func() Desired {
		for _, node := range s.nodes {
			if node.ID == "entry-example" {
				return node.Desired
			}
		}
		t.Fatal("entry missing")
		return Desired{}
	}
	phase := func(name string, primaryAllowed, otherAllowed bool, negativeTLS bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			desired := current()
			path := filepath.Join(t.TempDir(), "server.json")
			if err := os.WriteFile(path, desired.Config, 0600); err != nil {
				t.Fatal(err)
			}
			stop := startAuthenticationCore(t, ctx, driver, path, net.JoinHostPort(desired.Entry.RealityEndpoints[0].ListenAddress, fmt.Sprint(desired.Entry.RealityEndpoints[0].ListenPort)))
			defer stop()
			probe := func(auth, serverName string, trusted, want bool) {
				t.Helper()
				address, closeClient := startHysteriaClientFixture(t, ctx, driver, endpoint, auth, serverName, trusted)
				defer closeClient()
				before := requests.Load()
				err := probeAuthenticatedEntry(ctx, address, target.URL, roots)
				if want {
					if err != nil || requests.Load() != before+1 {
						t.Fatal("valid original HY2 credential could not reach verified TLS target", err)
					}
				} else if err == nil || requests.Load() != before {
					t.Fatal("disabled, unknown or TLS-invalid HY2 client reached target")
				}
			}
			probe(first.HysteriaAuth, endpoint.ServerName, true, primaryAllowed)
			probe(second.HysteriaAuth, endpoint.ServerName, true, otherAllowed)
			probe("anonymous-unknown-auth", endpoint.ServerName, true, false)
			if negativeTLS {
				probe(first.HysteriaAuth, "wrong.example.test", true, false)
				probe(first.HysteriaAuth, endpoint.ServerName, false, false)
			}
		})
		if t.Failed() {
			t.FailNow()
		}
	}
	phase("original-identities-and-TLS", true, true, true)
	disabled := firstPlan
	disabled.Enabled = false
	if _, err := s.UpdateAccountPlan(ctx, "account-example", 7, disabled); err != nil {
		t.Fatal(err)
	}
	phase("one-account-disabled", false, true, false)
	disabled = secondPlan
	disabled.Enabled = false
	if _, err := s.UpdateAccountPlan(ctx, "account-other", 1, disabled); err != nil {
		t.Fatal(err)
	}
	phase("all-accounts-disabled", false, false, false)
	if _, err := s.UpdateAccountPlan(ctx, "account-example", 8, firstPlan); err != nil {
		t.Fatal(err)
	}
	phase("original-primary-restored", true, false, false)
	if _, err := s.UpdateAccountPlan(ctx, "account-other", 2, secondPlan); err != nil {
		t.Fatal(err)
	}
	phase("both-original-identities-restored", true, true, false)
	updated := current()
	if updated.Entry.Credentials[0].HysteriaAuth != first.HysteriaAuth || updated.Entry.Credentials[1].HysteriaAuth != second.HysteriaAuth || updated.Entry.Credentials[0].ProtocolID != first.ProtocolID || updated.Entry.Credentials[1].ProtocolID != second.ProtocolID {
		t.Fatal("HY2 account updates regenerated an identity")
	}
}

func hysteriaAccountFixture(t *testing.T, certificateSource *httptest.Server) (*Store, Desired) {
	t.Helper()
	source, d, _, _ := subscriptionFixture(t, false)
	m := source.business.material
	m.Ownership = nil
	m.Endpoints = slices.Clone(m.Endpoints)
	m.Plan.Accounts = slices.Clone(m.Plan.Accounts)
	m.HysteriaSecrets = map[string]string{}
	plan := *d.clone().Entry
	private, err := x509.MarshalPKCS8PrivateKey(certificateSource.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := glivela.HysteriaEndpoint{ID: plan.RealityEndpoints[0].ID + "-hy2", EntryID: "entry-example", InboundTag: "hy2-example", ListenPort: 14445, AdvertiseHost: plan.RealityEndpoints[0].AdvertiseHost, AdvertisePort: 443, ServerName: "example.com", CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateSource.Certificate().Raw})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
	plan.HysteriaEndpoints = []glivela.HysteriaEndpoint{endpoint}
	for i := range plan.Credentials {
		material := &plan.Credentials[i]
		material.HysteriaAuth = "anonymous-hy2-" + material.Credential.ID
		material.HysteriaIdentity = glivela.Identity(material.HysteriaAuth)
		m.HysteriaSecrets[material.Credential.ID] = material.HysteriaAuth
	}
	for i := range m.Plan.Accounts {
		m.Plan.Accounts[i].HysteriaIdentities = map[string]string{}
		for _, credential := range m.Plan.Accounts[i].Credentials {
			m.Plan.Accounts[i].HysteriaIdentities[credential.ID] = glivela.Identity(m.HysteriaSecrets[credential.ID])
		}
	}
	m.Endpoints[0].Hysteria = &endpoint
	m.Endpoints[0].HysteriaEnabled = true
	expires, err := glivela.HysteriaCertificateNotAfter(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	m.Endpoints[0].CertificateNotAfter = expires.Format(time.RFC3339Nano)
	d, err = NewEntryDesired(plan, *d.EntryNetwork)
	if err != nil {
		t.Fatal(err)
	}
	s, d, _, _ := ownedSubscriptionFixture(t, m, d, false)
	return s, d
}

func startHysteriaClientFixture(t *testing.T, ctx context.Context, driver SystemdDriver, endpoint glivela.HysteriaEndpoint, auth, serverName string, trusted bool) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, port := listener.Addr().String(), listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	tlsSettings := map[string]any{"serverName": serverName, "alpn": []string{"h3"}, "minVersion": "1.3"}
	if trusted {
		tlsSettings["certificates"] = []any{map[string]any{"certificate": strings.Split(strings.TrimSpace(endpoint.CertificatePEM), "\n"), "usage": "verify"}}
	}
	config := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{map[string]any{"protocol": "hysteria", "settings": map[string]any{"version": 2, "address": "100.64.0.3", "port": endpoint.ListenPort}, "streamSettings": map[string]any{"method": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2, "auth": auth}, "tlsSettings": tlsSettings}}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hy2-client.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return address, startAuthenticationCore(t, ctx, driver, path, address)
}
