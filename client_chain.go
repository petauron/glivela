package glivela

import (
	"encoding/base64"
	"errors"
	"strings"
)

const IPv4ClientSS2022 = "ipv4-ss2022"
const IPv4ClientSS2022Method = "2022-blake3-aes-256-gcm"

// ClientChain contains a dedicated user credential, never the server transport key.
// It is stored only inside the encrypted business material.
type ClientChain struct {
	Shared bool `json:"shared,omitempty"`
	// IPv6SS2022 chains carry separately authorized, exact transport addresses.
	// Empty transport fields identify existing IPv4 client chains.
	Transport            string `json:"transport,omitempty"`
	SourceIPv6           string `json:"sourceIpv6,omitempty"`
	ServerIPv6           string `json:"serverIpv6,omitempty"`
	EntryCertificateID   string `json:"entryCertificateId,omitempty"`
	LandingCertificateID string `json:"landingCertificateId,omitempty"`
	ID                   string `json:"id"`
	AccountID            string `json:"accountId"`
	EntryID              string `json:"entryId"`
	EgressID             string `json:"egressId"`
	Name                 string `json:"name"`
	Port                 int    `json:"port"`
	Key                  string `json:"key"`
	Enabled              bool   `json:"enabled"`
}

func (c ClientChain) Validate() error {
	key, err := base64.StdEncoding.DecodeString(c.Key)
	validTransport := (c.Transport == "" || c.Transport == IPv4ClientSS2022) && c.SourceIPv6 == "" && c.ServerIPv6 == "" && c.EntryCertificateID == "" && c.LandingCertificateID == "" && (len(key) == 32 && !c.Shared || len(key) == 16 && c.Shared && c.Transport == IPv4ClientSS2022) && (c.Transport == "" || base64.StdEncoding.EncodeToString(key) == c.Key) ||
		c.Transport == "ipv6-ss2022" && PublicTransportIPv6(c.SourceIPv6) && PublicTransportIPv6(c.ServerIPv6) && c.SourceIPv6 != c.ServerIPv6 && ValidIdentity(c.EntryCertificateID) && ValidIdentity(c.LandingCertificateID) && c.EntryCertificateID != c.LandingCertificateID && len(key) == 16 && base64.StdEncoding.EncodeToString(key) == c.Key
	if !ValidIdentifier(c.ID) || !ValidIdentifier(c.AccountID) || !ValidIdentifier(c.EntryID) || !ValidIdentifier(c.EgressID) || c.EntryID == c.EgressID || strings.TrimSpace(c.Name) != c.Name || c.Name == "" || len([]rune(c.Name)) > 64 || strings.ContainsAny(c.Name, "\r\n") || c.Port < 24000 || c.Port > 24999 || err != nil || !validTransport || c.Shared && c.Port != 24000 {
		return errors.New("glivela: invalid client chain")
	}
	return nil
}

// ClientLanding is a client-only credential owned by one account. Original
// per-chain configuration stays retained for explicit forward recovery.
type ClientLanding struct {
	AccountID string `json:"accountId"`
	Key       string `json:"key"`
}

func (m ImportMaterial) EffectiveClientChain(c ClientChain) (ClientChain, error) {
	shared, ok := m.ClientLandings[c.EgressID]
	if !ok || m.DeletedClientChains[c.ID] {
		return c, nil
	}
	if shared.AccountID != c.AccountID {
		return ClientChain{}, errors.New("glivela: landing credential belongs to another account")
	}
	c.Shared, c.Port, c.Key = true, 24000, shared.Key
	if c.Transport == "" {
		c.Transport = IPv4ClientSS2022
	}
	if err := c.Validate(); err != nil {
		return ClientChain{}, err
	}
	return c, nil
}
