package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

// LoadManagementUI loads only the two digest-bound assets of this signed
// distribution. No URL, arbitrary filesystem root or remote UI is accepted.
// It is called once before NewServer; the same administrator mTLS guard owns
// both this UI and its API. The public subscription listener never serves it.
func (s *Store) LoadManagementUI(distribution string) error {
	if _, err := (SystemdDriver{Distribution: distribution}).resolveDistribution(runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(distribution, "runtime.json"))
	var metadata distributionMetadata
	if err != nil || decode(bytes.NewReader(raw), &metadata) != nil || len(metadata.UI) != 2 {
		return errors.New("control: signed management assets missing")
	}
	assets := map[string][]byte{}
	for path, name := range map[string]string{"/ui/glivela.js": "glivela-ui.js", "/ui/glivela.css": "glivela-ui.css"} {
		info, err := os.Lstat(filepath.Join(distribution, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 16<<20 {
			return errors.New("control: unsafe management asset")
		}
		data, err := os.ReadFile(filepath.Join(distribution, name))
		digest := sha256.Sum256(data)
		if err != nil || metadata.UI[name] != hex.EncodeToString(digest[:]) {
			return errors.New("control: management asset digest differs")
		}
		assets[path] = data
	}
	assets["/"] = []byte(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Glivela</title><link rel="stylesheet" href="/ui/glivela.css"></head><body><main id="glivela"></main><script type="module" src="/ui/start.js"></script></body></html>`)
	assets["/ui/start.js"] = []byte(`import { mountControl } from "/ui/glivela.js"; mountControl(document.getElementById("glivela"));`)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.managementUI != nil {
		return errors.New("control: management assets already loaded")
	}
	s.managementUI = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := assets[r.URL.Path]
		if !ok || r.URL.RawQuery != "" || r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "/ui/glivela.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		default:
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		}
		if r.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
	})
	return nil
}
