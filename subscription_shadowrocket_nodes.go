package glivela

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// RenderShadowrocketNodes retains the published inventory but uses native URI
// fields. Shadowrocket's Clash importer can select Chrome120 even when the
// source requests chrome plus ML-KEM; its native fingerprint field is explicit.
func RenderShadowrocketNodes(body []byte) ([]byte, error) {
	var document struct {
		Proxies []struct {
			Name       string `yaml:"name"`
			Type       string `yaml:"type"`
			Server     string `yaml:"server"`
			Port       int    `yaml:"port"`
			UUID       string `yaml:"uuid"`
			Password   string `yaml:"password"`
			Cipher     string `yaml:"cipher"`
			ServerName string `yaml:"servername"`
			SNI        string `yaml:"sni"`
			Flow       string `yaml:"flow"`
			Network    string `yaml:"network"`
			UDP        bool   `yaml:"udp"`
			Dialer     string `yaml:"dialer-proxy"`
			Reality    struct {
				PublicKey string `yaml:"public-key"`
				ShortID   string `yaml:"short-id"`
				SpiderX   string `yaml:"spider-x"`
			} `yaml:"reality-opts"`
		} `yaml:"proxies"`
	}
	if len(body) > maxSubscriptionBytes {
		return nil, errors.New("subscription: input too large")
	}
	if err := yaml.Unmarshal(body, &document); err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, p := range document.Proxies {
		if p.Name == "" || names[p.Name] {
			return nil, errors.New("subscription: invalid node inventory")
		}
		names[p.Name] = true
	}
	var out strings.Builder
	for _, p := range document.Proxies {
		if p.Server == "" || !validPort(p.Port) || p.Dialer != "" && !names[p.Dialer] {
			return nil, errors.New("subscription: invalid node reference")
		}
		u := url.URL{Scheme: p.Type, Host: net.JoinHostPort(p.Server, strconv.Itoa(p.Port)), Fragment: p.Name}
		q := url.Values{"udp": {strconv.FormatBool(p.UDP)}}
		if p.UDP {
			q.Set("udp", "1")
		} else {
			q.Set("udp", "0")
		}
		if p.Dialer != "" {
			q.Set("chain", p.Dialer)
		}
		switch p.Type {
		case "vless":
			if p.UUID == "" || p.Reality.PublicKey == "" || p.ServerName == "" || p.Network != "tcp" {
				return nil, errors.New("subscription: unsupported VLESS node")
			}
			u.User = url.User(p.UUID)
			q.Set("encryption", "none")
			q.Set("security", "reality")
			q.Set("type", "tcp")
			q.Set("sni", p.ServerName)
			q.Set("pbk", p.Reality.PublicKey)
			q.Set("sid", p.Reality.ShortID)
			q.Set("flow", p.Flow)
			q.Set("fingerprint", "Chrome140")
			if p.Reality.SpiderX != "" {
				q.Set("spx", p.Reality.SpiderX)
			}
		case "ss":
			if p.Cipher == "" || p.Password == "" {
				return nil, errors.New("subscription: invalid Shadowsocks node")
			}
			u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(p.Cipher + ":" + p.Password)))
		case "hysteria2":
			if p.Password == "" || p.SNI == "" {
				return nil, errors.New("subscription: invalid Hysteria node")
			}
			u.User = url.User(p.Password)
			q.Set("sni", p.SNI)
			q.Set("alpn", "h3")
			q.Set("insecure", "0")
		default:
			return nil, errors.New("subscription: unsupported Shadowrocket node")
		}
		u.RawQuery = q.Encode()
		out.WriteString(u.String())
		out.WriteByte('\n')
	}
	if out.Len() > maxSubscriptionBytes {
		return nil, errors.New("subscription: output too large")
	}
	return []byte(out.String()), nil
}
