package landing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
)

// LegacyDanteFirewall is a one-time ownership reader/remover for migration.
// It has no install operation. Callers must stop the old worker and fence its
// configuration writer before removing the verified table.
type LegacyDanteFirewall ServerFirewall

func (p LegacyDanteFirewall) identity() (string, string) {
	p.Sources = slices.Clone(p.Sources)
	slices.Sort(p.Sources)
	p.TCPOnlySources = slices.Clone(p.TCPOnlySources)
	slices.Sort(p.TCPOnlySources)
	raw, _ := json.Marshal(p)
	digest := sha256.Sum256(raw)
	return "vastora_landing_server_" + hex.EncodeToString(digest[:8]), "vastora-landing-server-v1:" + hex.EncodeToString(digest[:])
}

func (p LegacyDanteFirewall) objects() []map[string]nftObject {
	table, marker := p.identity()
	return ServerFirewall(p).renderObjects(table, marker, true)
}

// Verify requires the complete legacy policy, not just its table name or marker.
func (p LegacyDanteFirewall) Verify(ctx context.Context) error {
	return p.verify(ctx, runNFT)
}

func (p LegacyDanteFirewall) verify(ctx context.Context, run func(context.Context, []byte, ...string) ([]byte, error)) error {
	if err := ServerFirewall(p).validate(); err != nil {
		return err
	}
	raw, err := run(ctx, nil, "--json", "list", "ruleset")
	var document nftDocument
	if err != nil || len(raw) > nftOutputLimit || json.Unmarshal(raw, &document) != nil {
		return errors.New("landing: cannot inspect legacy firewall")
	}
	table, _ := p.identity()
	found, err := validateNFTPolicy(document, table, p.objects(), false)
	if err != nil || !found {
		return errors.New("landing: legacy firewall is missing or changed")
	}
	return nil
}

// Remove verifies again immediately before deletion and confirms disappearance.
// Absence is idempotent, whereas foreign or modified tables are never removed.
func (p LegacyDanteFirewall) Remove(ctx context.Context) error {
	return p.remove(ctx, runNFT)
}

func (p LegacyDanteFirewall) remove(ctx context.Context, run func(context.Context, []byte, ...string) ([]byte, error)) error {
	if err := ServerFirewall(p).validate(); err != nil {
		return err
	}
	table, _ := p.identity()
	return removeOwnedFirewall(ctx, run, table, p.objects())
}
