package glivela

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	MaxIdentifierLength  = 128
	MaxDisplayNameLength = 512
	MaxResetDays         = 3650
)

type PublishingMode string

const FixedMode PublishingMode = "fixed"

func (m PublishingMode) Valid() bool { return m == FixedMode }

type AccountPlan struct {
	TotalBytes int64 `json:"totalBytes"`
	ExpiryTime int64 `json:"expiryTime"`
	ResetDays  int   `json:"resetDays"`
	Enabled    bool  `json:"enabled"`
}

func (p AccountPlan) Validate() error {
	if p.TotalBytes < 0 || p.ExpiryTime < 0 || p.ResetDays < 0 || p.ResetDays > MaxResetDays {
		return errors.New("glivela: invalid account plan")
	}
	return nil
}

type Account struct {
	ID              string      `json:"id"`
	DisplayName     string      `json:"displayName"`
	Plan            AccountPlan `json:"plan"`
	DesiredRevision uint64      `json:"desiredRevision"`
	AppliedRevision uint64      `json:"appliedRevision"`
}

func (a Account) Validate() error {
	if !ValidIdentifier(a.ID) || !validDisplayName(a.DisplayName) || a.Plan.Validate() != nil || a.DesiredRevision == 0 || a.AppliedRevision > a.DesiredRevision {
		return errors.New("glivela: invalid account")
	}
	return nil
}

type CredentialKind string

const (
	NativeCredential CredentialKind = "native"
	RouteCredential  CredentialKind = "route"
)

type Credential struct {
	ID        string         `json:"id"`
	AccountID string         `json:"accountId"`
	Kind      CredentialKind `json:"kind"`
	User      string         `json:"user"`
	Identity  string         `json:"identity"`
	EntryID   string         `json:"entryId"`
	EgressID  string         `json:"egressId,omitempty"`
	Enabled   bool           `json:"enabled"`
}

func (c Credential) Validate() error {
	if !ValidIdentifier(c.ID) || !ValidIdentifier(c.AccountID) || !ValidIdentifier(c.EntryID) || !validUser(c.User) || !ValidIdentity(c.Identity) {
		return errors.New("glivela: invalid access credential")
	}
	switch c.Kind {
	case NativeCredential:
		if c.EgressID != "" {
			return errors.New("glivela: native credential cannot select an egress")
		}
	case RouteCredential:
		if !ValidIdentifier(c.EgressID) {
			return errors.New("glivela: route credential requires an egress")
		}
	default:
		return errors.New("glivela: unsupported credential kind")
	}
	return nil
}

type RouteGrant struct {
	ID           string         `json:"id"`
	AccountID    string         `json:"accountId"`
	EntryID      string         `json:"entryId"`
	EgressID     string         `json:"egressId"`
	IPv4EgressID string         `json:"ipv4EgressId,omitempty"`
	InboundTag   string         `json:"inboundTag"`
	Base         Credential     `json:"base"`
	Route        Credential     `json:"route"`
	Mode         PublishingMode `json:"mode"`
	Enabled      bool           `json:"enabled"`
	HideNative   bool           `json:"hideNative"`
	DesiredRev   uint64         `json:"desiredRevision"`
	AppliedRev   uint64         `json:"appliedRevision"`
	RuntimeGood  bool           `json:"runtimeHealthy"`
}

func (g RouteGrant) Validate() error {
	if !ValidIdentifier(g.ID) || !ValidIdentifier(g.AccountID) || !ValidIdentifier(g.EntryID) || !ValidIdentifier(g.EgressID) || !g.Mode.Valid() || !validInboundTag(g.InboundTag) || g.DesiredRev == 0 || g.AppliedRev > g.DesiredRev {
		return errors.New("glivela: invalid route grant")
	}
	if g.IPv4EgressID != "" && (!ValidIdentifier(g.IPv4EgressID) || g.IPv4EgressID == g.EgressID || g.IPv4EgressID == g.EntryID || g.EgressID == g.EntryID) {
		return errors.New("glivela: a composite route requires two independent exits")
	}
	if g.Base.Validate() != nil || g.Base.Kind != NativeCredential || g.Base.AccountID != g.AccountID || g.Base.EntryID != g.EntryID {
		return errors.New("glivela: invalid native route credential")
	}
	if g.Route.Validate() != nil || g.Route.Kind != RouteCredential || g.Route.AccountID != g.AccountID || g.Route.EntryID != g.EntryID || g.Route.EgressID != g.EgressID || g.Route.Identity == g.Base.Identity {
		return errors.New("glivela: invalid routed credential")
	}
	return nil
}

func (g RouteGrant) Publishable() bool {
	return g.Validate() == nil && g.Enabled && g.Base.Enabled && g.Route.Enabled && g.AppliedRev == g.DesiredRev && g.RuntimeGood
}

// Deployable reports whether the desired grant belongs in the next Xray
// projection. AppliedRev and RuntimeGood describe the previous receipt, so
// they deliberately do not gate creation of a newer desired configuration.
func (g RouteGrant) Deployable() bool {
	return g.Validate() == nil && g.Enabled && g.Base.Enabled && g.Route.Enabled
}

func ValidIdentifier(value string) bool {
	if value == "" || len(value) > MaxIdentifierLength {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func Identity(secret string) string {
	if secret == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(digest[:])
}

func ValidIdentity(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func RouteUser(grantID string) string {
	digest := sha256.Sum256([]byte(grantID))
	return "meridian-route-" + hex.EncodeToString(digest[:16])
}

func validDisplayName(value string) bool {
	return value != "" && len([]rune(value)) <= MaxDisplayNameLength && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func validInboundTag(value string) bool {
	return value != "" && len(value) <= MaxIdentifierLength && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func validUser(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}
