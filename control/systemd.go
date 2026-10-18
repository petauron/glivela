package control

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/petauron/glivela/landing"
)

// SystemdDriver invokes only an installed, hash-pinned official Xray and the
// dedicated Glivela service. No command or path comes from the node channel.
// The package installer must provision the matching unit and its firewall
// dependency; this adapter refuses unowned/replaced installation files.
type SystemdDriver struct {
	Binary       string `json:"binary"`
	BinarySHA256 string `json:"binarySha256"`
	UnitSHA256   string `json:"unitSha256"`
	WorkerUID    uint32 `json:"workerUid"`
	Interface    string `json:"interface"`
}

const xrayUnitPath = "/etc/systemd/system/glivela-xray.service"

// Ownership changes require explicit handover, not silent rule replacement.
func (d SystemdDriver) Binding() string {
	return "glivela-xray:" + strconv.FormatUint(uint64(d.WorkerUID), 10) + ":" + d.Interface
}

func verifyExecutableFile(path, expected string) error {
	if !filepath.IsAbs(path) {
		return errors.New("control: absolute executable path required")
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("control: artifact digest required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 128<<20 {
		return errors.New("control: unsafe installed artifact")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err = io.Copy(digest, file); err != nil {
		return err
	}
	if hex.EncodeToString(digest.Sum(nil)) != expected {
		return errors.New("control: installed artifact changed")
	}
	return nil
}

func (d SystemdDriver) Validate(ctx context.Context, config string) error {
	if err := verifyExecutableFile(d.Binary, d.BinarySHA256); err != nil {
		return err
	}
	// Output can include configuration/credentials. Discard it and expose only
	// a generic error; never attach unredacted Xray output to a receipt.
	if exec.CommandContext(ctx, d.Binary, "run", "-test", "-config", config).Run() != nil {
		return errors.New("control: Xray validation failed")
	}
	return nil
}

func (d SystemdDriver) service(ctx context.Context, action string) error {
	if err := verifyExecutableFile(xrayUnitPath, d.UnitSHA256); err != nil {
		return err
	}
	// Health polling must not rehash a multi-megabyte binary every cycle.
	// Validate/activation verify it before use; a health poll runs systemctl.
	if action != "is-active" {
		if err := verifyExecutableFile(d.Binary, d.BinarySHA256); err != nil {
			return err
		}
	}
	if exec.CommandContext(ctx, "/usr/bin/systemctl", action, "glivela-xray.service").Run() != nil {
		return errors.New("control: Xray service operation failed")
	}
	return nil
}
func (d SystemdDriver) policy(desired Desired) (landing.ServerFirewall, error) {
	if err := desired.Validate(); err != nil {
		return landing.ServerFirewall{}, err
	}
	worker, err := user.Lookup("glivela-xray")
	if err != nil || worker.Uid != strconv.FormatUint(uint64(d.WorkerUID), 10) {
		return landing.ServerFirewall{}, errors.New("control: dedicated worker identity differs")
	}
	iface, err := net.InterfaceByName(d.Interface)
	if err != nil {
		return landing.ServerFirewall{}, errors.New("control: private interface unavailable")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return landing.ServerFirewall{}, err
	}
	assigned := func(addresses []net.Addr, want string) bool {
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().String() == want {
				return true
			}
		}
		return false
	}
	if !assigned(addresses, desired.Landing.Address) {
		return landing.ServerFirewall{}, errors.New("control: landing listener is not on private interface")
	}
	all, err := net.InterfaceAddrs()
	if err != nil || !assigned(all, desired.Landing.EgressIP) {
		return landing.ServerFirewall{}, errors.New("control: egress source is not locally assigned")
	}
	return desired.Landing.Firewall(d.WorkerUID, d.Interface)
}

func (d SystemdDriver) Activate(ctx context.Context, desired Desired, previous *Desired) error {
	policy, err := d.policy(desired)
	if err != nil {
		return err
	}
	// No worker runs during rule replacement. Install the candidate before
	// removing the exact previous table; an interrupted switch remains closed.
	if err = d.service(ctx, "stop"); err != nil {
		return err
	}
	if err = policy.Install(ctx); err != nil {
		return err
	}
	if previous != nil && previous.Revision != desired.Revision {
		old, err := previous.Landing.Firewall(d.WorkerUID, d.Interface)
		if err != nil {
			return err
		}
		if err = old.Remove(ctx); err != nil {
			return err
		}
	}
	return d.service(ctx, "start")
}

func (d SystemdDriver) Stop(ctx context.Context, desired Desired) error {
	if err := d.service(ctx, "stop"); err != nil {
		return err
	}
	policy, err := desired.Landing.Firewall(d.WorkerUID, d.Interface)
	if err != nil {
		return err
	}
	return policy.Remove(ctx)
}

// Healthy is local runtime readiness, not end-to-end route acceptance. A local
// SOCKS probe would violate the exact mesh-source allowlist. Route acceptance
// must originate from an authorized entry and be tracked independently.
func (d SystemdDriver) Healthy(ctx context.Context, desired Desired) error {
	if err := d.service(ctx, "is-active"); err != nil {
		return err
	}
	policy, err := d.policy(desired)
	if err != nil {
		return err
	}
	return policy.Verify(ctx)
}

func probeSOCKSTLS(ctx context.Context, socksAddress, probeURL string, roots *x509.CertPool) error {
	endpoint, err := url.Parse(probeURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return errors.New("control: HTTPS acceptance target required")
	}
	if _, _, err = net.SplitHostPort(socksAddress); err != nil {
		return errors.New("control: invalid SOCKS acceptance endpoint")
	}
	proxy := &url.URL{Scheme: "socks5", Host: socksAddress}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint.String(), nil)
	if err != nil {
		return errors.New("control: invalid acceptance request")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("control: SOCKS TLS acceptance failed")
	}
	defer response.Body.Close()
	// Any actual HTTPS response proves the TLS path, including 401/403/404.
	// This does not claim the requested site's application is healthy.
	return nil
}
