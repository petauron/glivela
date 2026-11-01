package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	for id := range names {
		if !known[id] {
			return nil, errors.New("control: issued name has no retained endpoint")
		}
	}
	return names, nil
}
