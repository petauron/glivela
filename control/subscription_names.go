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

type SubscriptionLanding struct {
	RegionCode string `json:"regionCode"`
	NameSuffix string `json:"nameSuffix,omitempty"`
}

type subscriptionPresentation struct {
	Version  int                            `json:"version"`
	Names    map[string]string              `json:"names"`
	Landings map[string]SubscriptionLanding `json:"landings,omitempty"`
}

func parseSubscriptionPresentation(raw []byte) (subscriptionPresentation, error) {
	var v subscriptionPresentation
	invalid := errors.New("control: invalid issued subscription names")
	if len(raw) > controlStateLimit || decode(bytes.NewReader(raw), &v) != nil || v.Version != 1 || len(v.Names)+len(v.Landings) == 0 || len(v.Names) > 1024 || len(v.Landings) > 1024 {
		return subscriptionPresentation{}, invalid
	}
	seen := map[string]bool{}
	for id, name := range v.Names {
		if !glivela.ValidIdentifier(id) || !utf8.ValidString(name) || strings.TrimSpace(name) != name || name == "" || len([]rune(name)) > glivela.MaxDisplayNameLength || strings.ContainsFunc(name, unicode.IsControl) || name == "DIRECT" || name == "REJECT" || name == "\u8282\u70b9\u9009\u62e9" || seen[name] {
			return subscriptionPresentation{}, invalid
		}
		seen[name] = true
	}
	for id, landing := range v.Landings {
		if !glivela.ValidIdentifier(id) || !landing.valid() {
			return subscriptionPresentation{}, invalid
		}
	}
	return v, nil
}

func loadSubscriptionPresentation(directory string, m glivela.ImportMaterial) (subscriptionPresentation, error) {
	var raw json.RawMessage
	if err := readControlState(filepath.Join(directory, subscriptionNamesFile), &raw); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return subscriptionPresentation{Version: 1}, nil
		}
		return subscriptionPresentation{}, err
	}
	state, err := parseSubscriptionPresentation(raw)
	if err != nil {
		return subscriptionPresentation{}, err
	}
	known := map[string]bool{}
	// Archived display names remain evidence, never an executable endpoint.
	for id := range m.PrunedEntries {
		known[id] = true
	}
	for _, endpoint := range m.Endpoints {
		known[endpoint.Reality.EntryID] = true
	}
	for _, chain := range m.ClientChains {
		if chain.Transport != "ipv6-ss2022" {
			continue
		}
		if known[chain.ID] && state.Names[chain.ID] != "" {
			return subscriptionPresentation{}, errors.New("control: ambiguous issued name identity")
		}
		known[chain.ID] = true
	}
	for id := range m.ServerTransports {
		known[id] = true
	}
	for id := range state.Names {
		if !known[id] {
			return subscriptionPresentation{}, errors.New("control: issued name has no retained endpoint or chain")
		}
	}
	return state, nil
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
	current, err := loadSubscriptionPresentation(directory, s.business.material)
	if err != nil || !reflect.DeepEqual(current.Names, s.subscriptionNames) || !reflect.DeepEqual(current.Landings, s.subscriptionLandings) {
		return invalid
	}
	next := maps.Clone(current.Names)
	if next == nil {
		next = map[string]string{}
	}
	for id, name := range updates {
		old, present := expected[id]
		if !present || old != current.Names[id] || name == "" {
			return invalid
		}
		next[id] = name
	}
	state := subscriptionPresentation{Version: 1, Names: next, Landings: current.Landings}
	raw, err := json.Marshal(state)
	if err != nil {
		return invalid
	}
	if _, err = parseSubscriptionPresentation(raw); err != nil {
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
	for id := range s.business.material.ServerTransports {
		known[id] = true
	}
	for id := range next {
		if !known[id] {
			return invalid
		}
	}

	return s.saveSubscriptionPresentationLocked(ctx, current, state)
}

func (v SubscriptionLanding) valid() bool {
	return len(v.RegionCode) == 2 && v.RegionCode[0] >= 'A' && v.RegionCode[0] <= 'Z' && v.RegionCode[1] >= 'A' && v.RegionCode[1] <= 'Z' && utf8.ValidString(v.NameSuffix) && strings.TrimSpace(v.NameSuffix) == v.NameSuffix && len([]rune(v.NameSuffix)) <= glivela.MaxDisplayNameLength && !strings.ContainsAny(v.NameSuffix, "|｜") && !strings.ContainsFunc(v.NameSuffix, unicode.IsControl)
}

func (s *Store) subscriptionLandingLocked(id string) SubscriptionLanding {
	if value, ok := s.subscriptionLandings[id]; ok {
		return value
	}
	if s.business != nil && s.business.material.References.LandingSelection != nil {
		selection := s.business.material.References.LandingSelection
		return SubscriptionLanding{selection.LandingRegionCodes[id], selection.LandingNameSuffixes[id]}
	}
	return SubscriptionLanding{}
}

// SubscriptionLanding reads or updates presentation for one enrolled landing.
// A nil value reads; writes require an exact effective-value expectation.
func (s *Store) SubscriptionLanding(ctx context.Context, id string, expected, value *SubscriptionLanding) (SubscriptionLanding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: landing presentation changed or unavailable")
	if ctx.Err() != nil || s.business == nil || s.business.faulted || s.business.material.Ownership == nil {
		return SubscriptionLanding{}, invalid
	}
	known := false
	for _, node := range s.nodes {
		if node.ID == id && node.Desired.Landing != nil {
			known = true
			break
		}
	}
	if !known {
		return SubscriptionLanding{}, invalid
	}
	current := s.subscriptionLandingLocked(id)
	if value == nil {
		return current, nil
	}
	if expected == nil || *expected != current || !value.valid() {
		return SubscriptionLanding{}, invalid
	}
	directory := filepath.Dir(s.path)
	state, err := loadSubscriptionPresentation(directory, s.business.material)
	if err != nil || !reflect.DeepEqual(state.Names, s.subscriptionNames) || !reflect.DeepEqual(state.Landings, s.subscriptionLandings) {
		return SubscriptionLanding{}, invalid
	}
	if *value == current {
		return current, nil
	}
	next := state
	next.Landings = maps.Clone(state.Landings)
	if next.Landings == nil {
		next.Landings = map[string]SubscriptionLanding{}
	}
	next.Landings[id] = *value
	if err = s.saveSubscriptionPresentationLocked(ctx, state, next); err != nil {
		return SubscriptionLanding{}, err
	}
	return *value, nil
}

func (s *Store) saveSubscriptionPresentationLocked(ctx context.Context, current, next subscriptionPresentation) error {
	invalid := errors.New("control: subscription presentation unavailable")
	raw, err := json.Marshal(next)
	if err != nil {
		return invalid
	}
	if _, err = parseSubscriptionPresentation(raw); err != nil {
		return invalid
	}
	// Keep selectable identities and ordering while validating both outputs.
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
	s.subscriptionNames = next.Names
	s.subscriptionLandings = next.Landings
	defer func() { s.subscriptionNames = current.Names; s.subscriptionLandings = current.Landings }()
	for id, items := range before {
		content, err := s.subscriptionAccountLocked(ctx, id, true)
		if err != nil || !slices.EqualFunc(items, content.items, func(a, b glivela.SubscriptionItem) bool {
			return a.ID == b.ID && a.Kind == b.Kind && a.Protocol == b.Protocol
		}) {
			return invalid
		}
		if _, err = s.subscriptionAccountLocked(ctx, id, false); err != nil {
			return invalid
		}
	}
	directory := filepath.Dir(s.path)
	writeErr := writeControlState(filepath.Join(directory, subscriptionNamesFile), next)
	observed, readErr := loadSubscriptionPresentation(directory, s.business.material)
	if readErr == nil && reflect.DeepEqual(observed, next) {
		current = observed
		return writeErr
	}
	if readErr == nil && reflect.DeepEqual(observed, current) && writeErr != nil {
		return writeErr
	}
	s.business.faulted = true
	return invalid
}
