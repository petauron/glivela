package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

// controllerHandler separates locally enrolled management certificates from
// node certificates on the same authenticated Glivela listener. Neither a
// request field nor a CA signature alone grants administrative authority.
func controllerHandler(store *Store, administrators []string) (http.Handler, error) {
	if store == nil || len(administrators) > 16 {
		return nil, errors.New("control: invalid controller administration")
	}
	admins := make(map[string]bool, len(administrators))
	for _, certificate := range administrators {
		if !glivela.ValidIdentity(certificate) || admins[certificate] {
			return nil, errors.New("control: invalid management certificate inventory")
		}
		admins[certificate] = true
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for certificate, node := range store.nodes {
		if admins[certificate] {
			return nil, errors.New("control: management and node identities must differ")
		}
		for _, check := range node.Checks {
			if admins[check.CertificateID] {
				return nil, errors.New("control: management and verifier identities must differ")
			}
		}
		for _, entry := range node.RouteEntries {
			if admins[entry.CertificateID] {
				return nil, errors.New("control: management and entry identities must differ")
			}
		}
	}
	nodes := Handler(store)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client authentication required", http.StatusUnauthorized)
			return
		}
		admin := admins[CertificateID(r.TLS.PeerCertificates[0])]
		if !strings.HasPrefix(r.URL.Path, "/v1/admin/") {
			if admin {
				http.Error(w, "management identity cannot report node state", http.StatusForbidden)
				return
			}
			nodes.ServeHTTP(w, r)
			return
		}
		if !admin {
			http.Error(w, "management authorization required", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			http.Error(w, "unsupported management request", http.StatusNotFound)
			return
		}
		switch r.URL.Path {
		case "/v1/admin/landings":
			var request struct {
				ID            string                `json:"id"`
				CertificateID string                `json:"certificateId"`
				Plan          landing.Plan          `json:"plan"`
				RouteEntries  map[string]RouteEntry `json:"routeEntries"`
			}
			if decode(http.MaxBytesReader(w, r.Body, 64<<10), &request) != nil || !glivela.ValidIdentifier(request.ID) || !glivela.ValidIdentity(request.CertificateID) || admins[request.CertificateID] {
				http.Error(w, "invalid landing identity or plan", http.StatusBadRequest)
				return
			}
			desired, err := NewDesired(request.Plan)
			if err != nil {
				http.Error(w, "invalid landing policy", http.StatusBadRequest)
				return
			}
			for _, entry := range request.RouteEntries {
				if admins[entry.CertificateID] {
					http.Error(w, "entry identity required", http.StatusBadRequest)
					return
				}
			}
			if store.Put(Node{ID: request.ID, CertificateID: request.CertificateID, Desired: desired, RouteEntries: request.RouteEntries}) != nil {
				http.Error(w, "landing update refused", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(struct {
				Revision     uint64 `json:"revision"`
				ConfigSHA256 string `json:"configSha256"`
			}{desired.Revision, desired.ConfigSHA256})
		case "/v1/admin/route-checks":
			var request struct {
				Checks []RouteCheck `json:"checks"`
			}
			if decode(http.MaxBytesReader(w, r.Body, 256<<10), &request) != nil {
				http.Error(w, "invalid route inventory", http.StatusBadRequest)
				return
			}
			for _, check := range request.Checks {
				if admins[check.CertificateID] {
					http.Error(w, "verifier identity required", http.StatusBadRequest)
					return
				}
			}
			if store.AssignRouteChecks(request.Checks) != nil {
				http.Error(w, "route assignment refused", http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusAccepted) // Queued is not verified or migrated.
		case "/v1/admin/route-acceptance":
			var request struct {
				LandingID    string `json:"landingId"`
				SnapshotID   string `json:"snapshotId"`
				Revision     uint64 `json:"revision"`
				ConfigSHA256 string `json:"configSha256"`
			}
			if decode(http.MaxBytesReader(w, r.Body, 4096), &request) != nil {
				http.Error(w, "invalid acceptance identity", http.StatusBadRequest)
				return
			}
			status, err := store.AcceptLandingRoutes(request.LandingID, request.SnapshotID, request.Revision, request.ConfigSHA256)
			if err != nil {
				http.Error(w, "route acceptance unavailable", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(status)
		default:
			http.Error(w, "unsupported management request", http.StatusNotFound)
		}
	}), nil
}
