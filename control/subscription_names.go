package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	glivela "github.com/petauron/glivela"
)

// Issued display names are operator data, never vendor aliases compiled into
// the public program. This private file is loaded before any subscription binds.
const subscriptionNamesFile = "subscription-names.json"

func parseSubscriptionNames(raw []byte) (map[string]string, error) {
	var v struct {
		Version int               `json:"version"`
		Names   map[string]string `json:"names"`
	}
	invalid := errors.New("control: invalid issued subscription names")
	if len(raw) > controlStateLimit || decode(bytes.NewReader(raw), &v) != nil || v.Version != 1 || len(v.Names) == 0 || len(v.Names) > 1024 {
		return nil, invalid
	}
	seen := map[string]bool{}
	for id, name := range v.Names {
		if !glivela.ValidIdentifier(id) || !utf8.ValidString(name) || strings.TrimSpace(name) != name || name == "" || len([]rune(name)) > glivela.MaxDisplayNameLength || strings.ContainsFunc(name, unicode.IsControl) || name == "DIRECT" || name == "REJECT" || name == "\u8282\u70b9\u9009\u62e9" || seen[name] {
			return nil, invalid
		}
		seen[name] = true
	}
	return v.Names, nil
}

func loadSubscriptionNames(directory string, m glivela.ImportMaterial) (map[string]string, error) {
	var raw json.RawMessage
	if err := readControlState(filepath.Join(directory, subscriptionNamesFile), &raw); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	names, err := parseSubscriptionNames(raw)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, endpoint := range m.Endpoints {
		known[endpoint.Reality.EntryID] = true
	}
	for _, chain := range m.ClientChains {
		if chain.Transport != "ipv6-ss2022" {
			continue
		}
		if known[chain.ID] && names[chain.ID] != "" {
			return nil, errors.New("control: ambiguous issued name identity")
		}
		known[chain.ID] = true
	}
	for id := range names {
		if !known[id] {
			return nil, errors.New("control: issued name has no retained endpoint or chain")
		}
	}
	return names, nil
}

// ChangeSubscriptionNames changes presentation only. It does not rewrite the
// business ledger or project a node configuration. Expectations fence stale
// operator edits, and every currently available subscription is rendered before
// the private file is atomically replaced.
func (s *Store) ChangeSubscriptionNames(ctx context.Context, expected, updates map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: subscription names changed or unavailable")
	if ctx.Err() != nil || s.business == nil || s.business.faulted || s.business.material.Ownership == nil || len(updates) == 0 || len(updates) > 1024 || len(expected) != len(updates) {
		return invalid
	}
	directory := filepath.Dir(s.path)
	current, err := loadSubscriptionNames(directory, s.business.material)
	if err != nil || !reflect.DeepEqual(current, s.subscriptionNames) {
		return invalid
	}
	next := maps.Clone(current)
	if next == nil {
		next = map[string]string{}
	}
	for id, name := range updates {
		old, present := expected[id]
		if !present || old != current[id] || name == "" {
			return invalid
		}
		next[id] = name
	}
	state := struct {
		Version int               `json:"version"`
		Names   map[string]string `json:"names"`
	}{1, next}
	raw, err := json.Marshal(state)
	if err != nil {
		return invalid
	}
	if _, err = parseSubscriptionNames(raw); err != nil {
		return invalid
	}
	known := map[string]bool{}
	for _, endpoint := range s.business.material.Endpoints {
		known[endpoint.Reality.EntryID] = true
	}
	for _, chain := range s.business.material.ClientChains {
		if chain.Transport != "ipv6-ss2022" {
			continue
		}
		if known[chain.ID] && next[chain.ID] != "" {
			return invalid
		}
		known[chain.ID] = true
	}
	for id := range next {
		if !known[id] {
			return invalid
		}
	}

	// Validate generated names and retain each selectable identity and order.
	before := map[string][]glivela.SubscriptionItem{}
	for _, account := range s.business.material.Plan.Accounts {
		content, err := s.subscriptionAccountLocked(ctx, account.Account.ID, true)
		if errors.Is(err, errSubscriptionMissing) {
			continue
		}
		if err != nil {
			return invalid
		}
		before[account.Account.ID] = content.items
	}
	if len(before) == 0 {
		return invalid
	}
	s.subscriptionNames = next
	for id, items := range before {
		content, err := s.subscriptionAccountLocked(ctx, id, true)
		if err != nil || !slices.EqualFunc(items, content.items, func(a, b glivela.SubscriptionItem) bool {
			return a.ID == b.ID && a.Kind == b.Kind && a.Protocol == b.Protocol
		}) {
			s.subscriptionNames = current
			return invalid
		}
		if _, err = s.subscriptionAccountLocked(ctx, id, false); err != nil {
			s.subscriptionNames = current
			return invalid
		}
	}
	s.subscriptionNames = current
	path := filepath.Join(directory, subscriptionNamesFile)
	writeErr := writeControlState(path, state)
	observed, readErr := loadSubscriptionNames(directory, s.business.material)
	if readErr == nil && reflect.DeepEqual(observed, next) {
		s.subscriptionNames = observed
		return writeErr
	}
	if readErr == nil && reflect.DeepEqual(observed, current) && writeErr != nil {
		return writeErr
	}
	s.business.faulted = true
	return invalid
}
