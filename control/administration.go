package control

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/landing"
)

type accountPlanInput struct {
	TotalBytes *int64 `json:"totalBytes,string"`
	ExpiryTime *int64 `json:"expiryTime,string"`
	ResetDays  *int   `json:"resetDays"`
	Enabled    *bool  `json:"enabled"`
}

func (p *accountPlanInput) value() (glivela.AccountPlan, error) {
	if p == nil || p.TotalBytes == nil || p.ExpiryTime == nil || p.ResetDays == nil || p.Enabled == nil {
		return glivela.AccountPlan{}, errors.New("control: complete account plan required")
	}
	plan := glivela.AccountPlan{TotalBytes: *p.TotalBytes, ExpiryTime: *p.ExpiryTime, ResetDays: *p.ResetDays, Enabled: *p.Enabled}
	return plan, plan.Validate()
}

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
		if admin && store.managementUI != nil && (r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/ui/")) {
			store.managementUI.ServeHTTP(w, r)
			return
		}
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
		contentType, _, contentErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentErr != nil || contentType != "application/json" || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "https://"+r.Host || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "same-origin JSON management request required", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/v1/admin/availability":
			var input struct {
				ID               string    `json:"id"`
				Reason           string    `json:"reason"`
				ResumeAt         time.Time `json:"resumeAt"`
				ExpectedRevision uint64    `json:"expectedRevision,string"`
			}
			if decode(http.MaxBytesReader(w, r.Body, 4096), &input) != nil {
				http.Error(w, "invalid availability request", http.StatusBadRequest)
				return
			}
			if input.ID != "" {
				if err := store.SetAvailability(input.ID, input.Reason, input.ResumeAt, input.ExpectedRevision); err != nil {
					http.Error(w, "availability change refused", http.StatusConflict)
					return
				}
			}
			store.mu.Lock()
			defer store.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(store.availability)
		case "/v1/admin/backup":
			var input struct{}
			if decode(http.MaxBytesReader(w, r.Body, 4096), &input) != nil {
				http.Error(w, "invalid backup request", http.StatusBadRequest)
				return
			}
			if store.Business().State != "owned-unverified" || store.BackupController(time.Now()) != nil {
				http.Error(w, "controller backup not confirmed", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				BackedUp bool `json:"backedUp"`
			}{true})
		case "/v1/admin/account-subscription":
			var request struct {
				AccountID string `json:"accountId"`
			}
			if decode(http.MaxBytesReader(w, r.Body, 4096), &request) != nil {
				http.Error(w, "invalid subscription disclosure request", http.StatusBadRequest)
				return
			}
			link, err := store.SubscriptionURL(r.Context(), request.AccountID)
			if err != nil {
				http.Error(w, "subscription identity or published origin unavailable", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				URL string `json:"subscriptionUrl"`
			}{link})
		case "/v1/admin/routes":
			var request RouteChange
			if decode(http.MaxBytesReader(w, r.Body, 8192), &request) != nil {
				http.Error(w, "invalid route request", http.StatusBadRequest)
				return
			}
			status, err := store.ChangeRoute(r.Context(), request)
			if err != nil {
				http.Error(w, "route change not confirmed", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(status)
		case "/v1/admin/accounts":
			var request struct {
				ID       string            `json:"id"`
				Name     string            `json:"name"`
				EntryIDs []string          `json:"entryIds"`
				Plan     *accountPlanInput `json:"plan"`
			}
			if decode(http.MaxBytesReader(w, r.Body, 256<<10), &request) != nil {
				http.Error(w, "invalid account creation request", http.StatusBadRequest)
				return
			}
			plan, err := request.Plan.value()
			if err != nil {
				http.Error(w, "complete account plan required", http.StatusBadRequest)
				return
			}
			created, err := store.CreateAccount(r.Context(), request.ID, request.Name, plan, request.EntryIDs)
			if err != nil {
				http.Error(w, "account creation not confirmed", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(created)
		case "/v1/admin/account-reset":
			var request struct {
				AccountID        string `json:"accountId"`
				ExpectedRevision uint64 `json:"expectedRevision,string"`
			}
			if decode(http.MaxBytesReader(w, r.Body, 4096), &request) != nil {
				http.Error(w, "invalid account reset request", http.StatusBadRequest)
				return
			}
			status, err := store.ResetAccountUsage(r.Context(), request.AccountID, request.ExpectedRevision)
			if err != nil {
				http.Error(w, "account reset not confirmed", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(status)
		case "/v1/admin/account-plan":
			var request struct {
				AccountID        string            `json:"accountId"`
				ExpectedRevision uint64            `json:"expectedRevision,string"`
				Plan             *accountPlanInput `json:"plan"`
			}
			if decode(http.MaxBytesReader(w, r.Body, 4096), &request) != nil || request.Plan == nil || request.Plan.TotalBytes == nil || request.Plan.ExpiryTime == nil || request.Plan.ResetDays == nil || request.Plan.Enabled == nil || !glivela.ValidIdentifier(request.AccountID) || request.ExpectedRevision == 0 {
				http.Error(w, "complete account plan required", http.StatusBadRequest)
				return
			}
			plan := glivela.AccountPlan{TotalBytes: *request.Plan.TotalBytes, ExpiryTime: *request.Plan.ExpiryTime, ResetDays: *request.Plan.ResetDays, Enabled: *request.Plan.Enabled}
			if plan.Validate() != nil {
				http.Error(w, "invalid account plan", http.StatusBadRequest)
				return
			}
			status, err := store.UpdateAccountPlan(r.Context(), request.AccountID, request.ExpectedRevision, plan)
			if err != nil {
				http.Error(w, "account update not confirmed", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(status)
		case "/v1/admin/entries/refresh-prepared-quota":
			var request struct {
				ID              string          `json:"id"`
				CertificateID   string          `json:"certificateId"`
				ExpectedCutover time.Time       `json:"expectedCutoverAt"`
				Quota           *EntryQuotaSeed `json:"quota"`
				RouteHealth     map[string]bool `json:"routeHealth"`
			}
			if decode(http.MaxBytesReader(w, r.Body, 4096), &request) != nil || request.Quota == nil || !glivela.ValidIdentifier(request.ID) || !glivela.ValidIdentity(request.CertificateID) || admins[request.CertificateID] {
				http.Error(w, "invalid prepared quota refresh", http.StatusBadRequest)
				return
			}
			if err := store.RefreshPreparedEntryQuota(request.ID, request.CertificateID, request.ExpectedCutover, *request.Quota, request.RouteHealth); err != nil {
				http.Error(w, "prepared quota refresh refused", http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/v1/admin/probe-targets":
			var request ProbeUpdate
			if decode(http.MaxBytesReader(w, r.Body, maxMessage), &request) != nil {
				http.Error(w, "invalid probe update", http.StatusBadRequest)
				return
			}
			if store.UpdateProbeTargets(request) != nil {
				http.Error(w, "probe update refused", http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		case "/v1/admin/private-transport":
			var request TransportSwitch
			if decode(http.MaxBytesReader(w, r.Body, maxMessage), &request) != nil {
				http.Error(w, "invalid transport request", http.StatusBadRequest)
				return
			}
			if store.SwitchPrivateTransport(request) != nil {
				http.Error(w, "transport switch refused", http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		case "/v1/admin/entries":
			var request struct {
				ID            string           `json:"id"`
				CertificateID string           `json:"certificateId"`
				Plan          glivela.XrayPlan `json:"plan"`
				Network       *EntryNetwork    `json:"network"`
				Quota         *EntryQuotaSeed  `json:"quota,omitempty"`
			}
			if decode(http.MaxBytesReader(w, r.Body, maxMessage), &request) != nil || request.Network == nil || !glivela.ValidIdentifier(request.ID) || !glivela.ValidIdentity(request.CertificateID) || admins[request.CertificateID] {
				http.Error(w, "invalid entry identity or plan", http.StatusBadRequest)
				return
			}
			desired, err := NewEntryDesired(request.Plan, *request.Network)
			if err != nil {
				http.Error(w, "invalid entry policy", http.StatusBadRequest)
				return
			}
			var quota *EntryQuota
			if request.Quota != nil {
				quota, desired, err = newEntryQuota(*request.Quota, desired)
				if err != nil {
					http.Error(w, "invalid entry quota handover", http.StatusBadRequest)
					return
				}
			}
			if err := store.Put(Node{ID: request.ID, CertificateID: request.CertificateID, Desired: desired, EntryQuota: quota}); err != nil {
				http.Error(w, "entry update refused", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(struct {
				Revision     uint64 `json:"revision"`
				ConfigSHA256 string `json:"configSha256"`
			}{desired.Revision, desired.ConfigSHA256})
		case "/v1/admin/business":
			var request struct{}
			if decode(http.MaxBytesReader(w, r.Body, 4096), &request) != nil {
				http.Error(w, "invalid business inventory request", http.StatusBadRequest)
				return
			}
			raw, err := json.Marshal(store.Business())
			if err != nil || len(raw) > maxMessage {
				http.Error(w, "business inventory unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
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
