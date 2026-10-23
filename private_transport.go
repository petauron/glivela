package glivela

import (
	"encoding/base64"
	"errors"
)

const SS2022Method = "2022-blake3-aes-128-gcm"

// PrivateTransport belongs only to the entry-to-landing connection. Its key
// must never be included in public subscriptions or diagnostic output. Empty
// values describe the retained pre-migration SOCKS configuration, not fallback.
type PrivateTransport struct {
	Protocol string `json:"protocol,omitempty"`
	Key      string `json:"key,omitempty"`
}

func (t PrivateTransport) Validate() error {
	if t.Protocol == "" && t.Key == "" {
		return nil
	}
	key, err := base64.StdEncoding.Strict().DecodeString(t.Key)
	if t.Protocol != "ss2022" || err != nil || len(key) != 16 || base64.StdEncoding.EncodeToString(key) != t.Key {
		return errors.New("glivela: invalid private transport")
	}
	return nil
}

func (p RoutePeer) outbound(tag string) map[string]any {
	server := map[string]any{"address": p.Address, "port": p.Port}
	protocol := "socks"
	if p.Transport.Protocol == "ss2022" {
		protocol = "shadowsocks"
		server["method"], server["password"] = SS2022Method, p.Transport.Key
	}
	return map[string]any{"protocol": protocol, "tag": tag, "settings": map[string]any{"servers": []any{server}}}
}
