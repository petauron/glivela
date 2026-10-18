package glivela

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
)

type ImportAccount struct {
	Account                      Account           `json:"account"`
	SubscriptionTokenFingerprint string            `json:"subscriptionTokenFingerprint"`
	Credentials                  []Credential      `json:"credentials"`
	HysteriaIdentities           map[string]string `json:"hysteriaIdentities,omitempty"`
	Grants                       []RouteGrant      `json:"grants"`
	Usage                        []UsageMember     `json:"usage"`
}

type ImportPlan struct {
	Accounts []ImportAccount `json:"accounts"`
	SHA256   string          `json:"sha256"`
}

// PlanImport validates a complete one-time authority transfer before a caller
// writes any state. It carries only the subscription-token fingerprint; the
// caller must move the raw token directly between encrypted stores.
func PlanImport(accounts []ImportAccount) (ImportPlan, error) {
	if len(accounts) > 10000 {
		return ImportPlan{}, errors.New("glivela: invalid import inventory")
	}
	plan := ImportPlan{Accounts: slices.Clone(accounts)}
	if plan.Accounts == nil {
		plan.Accounts = []ImportAccount{}
	}
	slices.SortFunc(plan.Accounts, func(a, b ImportAccount) int { return strings.Compare(a.Account.ID, b.Account.ID) })
	seenAccounts := map[string]bool{}
	seenCredentialIDs := map[string]bool{}
	seenUsers := map[string]bool{}
	seenEntryIdentities := map[string]bool{}
	seenHysteriaIdentities := map[string]bool{}
	seenTokens := map[string]bool{}
	seenGrantIDs := map[string]bool{}
	for accountIndex := range plan.Accounts {
		item := &plan.Accounts[accountIndex]
		if item.Account.Validate() != nil || seenAccounts[item.Account.ID] || !validTokenFingerprint(item.SubscriptionTokenFingerprint) || seenTokens[item.SubscriptionTokenFingerprint] || len(item.Credentials) > 1024 {
			return ImportPlan{}, errors.New("glivela: conflicting import account")
		}
		seenAccounts[item.Account.ID], seenTokens[item.SubscriptionTokenFingerprint] = true, true
		item.Credentials = slices.Clone(item.Credentials)
		item.HysteriaIdentities = maps.Clone(item.HysteriaIdentities)
		item.Grants = slices.Clone(item.Grants)
		item.Usage = slices.Clone(item.Usage)
		slices.SortFunc(item.Credentials, func(a, b Credential) int { return strings.Compare(a.ID, b.ID) })
		slices.SortFunc(item.Grants, func(a, b RouteGrant) int { return strings.Compare(a.ID, b.ID) })
		slices.SortFunc(item.Usage, func(a, b UsageMember) int { return strings.Compare(a.CredentialID, b.CredentialID) })
		credentialByID := map[string]Credential{}
		for _, credential := range item.Credentials {
			entryIdentity := credential.EntryID + "\x00" + string(credential.Identity)
			if credential.Validate() != nil || credential.AccountID != item.Account.ID || seenCredentialIDs[credential.ID] || seenUsers[credential.User] || seenEntryIdentities[entryIdentity] {
				return ImportPlan{}, errors.New("glivela: conflicting import credential")
			}
			seenCredentialIDs[credential.ID], seenUsers[credential.User], seenEntryIdentities[entryIdentity] = true, true, true
			credentialByID[credential.ID] = credential
		}
		for credentialID, identity := range item.HysteriaIdentities {
			credential, exists := credentialByID[credentialID]
			entryIdentity := credential.EntryID + "\x00" + identity
			if !exists || credential.Kind != NativeCredential || !ValidIdentity(identity) || seenHysteriaIdentities[entryIdentity] {
				return ImportPlan{}, errors.New("glivela: conflicting import Hysteria credential")
			}
			seenHysteriaIdentities[entryIdentity] = true
		}
		for _, grant := range item.Grants {
			base, hasBase := credentialByID[grant.Base.ID]
			route, hasRoute := credentialByID[grant.Route.ID]
			if grant.Validate() != nil || grant.AccountID != item.Account.ID || seenGrantIDs[grant.ID] || !hasBase || !hasRoute || base != grant.Base || route != grant.Route {
				return ImportPlan{}, errors.New("glivela: conflicting import route grant")
			}
			seenGrantIDs[grant.ID] = true
		}
		if len(item.Usage) != len(item.Credentials) {
			return ImportPlan{}, errors.New("glivela: incomplete import usage ledger")
		}
		for _, member := range item.Usage {
			if _, exists := credentialByID[member.CredentialID]; !exists || member.Baseline < 0 || member.Observed < member.Baseline {
				return ImportPlan{}, errors.New("glivela: invalid import usage ledger")
			}
		}
		// An account can exist before the first endpoint is installed. Preserve
		// that configuration and token without inventing a credential or traffic
		// observation. Live quota/subscription projection still rejects an empty
		// credential inventory; importing it does not grant network access.
		if len(item.Credentials) > 0 {
			if _, err := ProjectQuota(item.Account.Plan, item.Usage); err != nil {
				return ImportPlan{}, err
			}
		}
	}
	encoded, err := json.Marshal(plan.Accounts)
	if err != nil {
		return ImportPlan{}, errors.New("glivela: cannot encode import plan")
	}
	digest := sha256.Sum256(encoded)
	plan.SHA256 = hex.EncodeToString(digest[:])
	return plan, nil
}

func SubscriptionTokenFingerprint(token string) string {
	if token == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func validTokenFingerprint(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}
