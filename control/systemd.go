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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// SystemdDriver invokes only an installed, hash-pinned official Xray and the
// dedicated Glivela service. No command or path comes from the node channel.
// The package installer must provision the matching unit and its firewall
// dependency; this adapter refuses unowned/replaced installation files.
type SystemdDriver struct {
	Binary       string `json:"binary"`
	BinarySHA256 string `json:"binarySha256"`
	UnitSHA256   string `json:"unitSha256"`
	SOCKSAddress string `json:"socksAddress"`
	ProbeURL     string `json:"probeUrl"`
}

const xrayUnitPath = "/etc/systemd/system/glivela-xray.service"

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
func (d SystemdDriver) Activate(ctx context.Context) error { return d.service(ctx, "restart") }
func (d SystemdDriver) Stop(ctx context.Context) error     { return d.service(ctx, "stop") }

func (d SystemdDriver) Healthy(ctx context.Context) error {
	if err := d.service(ctx, "is-active"); err != nil {
		return err
	}
	return probeSOCKSTLS(ctx, d.SOCKSAddress, d.ProbeURL, nil)
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
