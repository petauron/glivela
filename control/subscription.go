package control

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	glivela "github.com/petauron/glivela"
)

var errSubscriptionMissing = errors.New("control: subscription unavailable")
var errSubscriptionUnverified = errors.New("control: subscription not verified")

type subscriptionContent struct {
	body                  []byte
	contentType, userInfo string
}

// The public TLS edge belongs to the installer's existing generic ingress.
// This token-bearing origin must never bind a wildcard or public interface.
func NewSubscriptionServer(address string, store *Store) (*http.Server, error) {
	host, _, err := net.SplitHostPort(address)
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || ip.Zone() != "" || !(ip.IsPrivate() || ip.IsLoopback() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip)) || store == nil {
		return nil, errors.New("control: private subscription origin required")
	}
	return &http.Server{Addr: address, Handler: SubscriptionHandler(store), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}, nil
}

// SubscriptionHandler serves only token-authorized subscription downloads.
// It has no management/node endpoints and never accepts forwarded identity.
// The installer may publish this private origin through its generic HTTPS
// ingress; it must not weaken the separate controller's mutual TLS listener.
func SubscriptionHandler(store *Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token, ok := strings.CutPrefix(r.URL.Path, "/sub/")
		if !ok || token == "" || len(token) > 512 || strings.ContainsAny(token, "/\x00\r\n") || store == nil {
			http.NotFound(w, r)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		// Reject malformed escaping and duplicate/unknown selectors rather than
		// interpreting the same sensitive request differently at the origin.
		if err != nil {
			http.Error(w, "invalid format", http.StatusBadRequest)
			return
		}
		for key, values := range query {
			if (key != "format" && key != "target") || len(values) != 1 {
				http.Error(w, "invalid format", http.StatusBadRequest)
				return
			}
		}
		format, target := strings.ToLower(strings.TrimSpace(query.Get("format"))), strings.ToLower(strings.TrimSpace(query.Get("target")))
		if format != "" && format != "mihomo" && format != "links" || target != "" && target != "mihomo" && target != "clash" {
			http.Error(w, "invalid format", http.StatusBadRequest)
			return
		}
		mihomo := format == "mihomo" || target != "" || format == "" && (strings.Contains(strings.ToLower(r.UserAgent()), "clash") || strings.Contains(strings.ToLower(r.UserAgent()), "mihomo"))
		content, err := store.subscription(r.Context(), token, mihomo)
		if errors.Is(err, errSubscriptionMissing) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "subscription temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", content.contentType)
		w.Header().Set("Subscription-Userinfo", content.userInfo)
		w.Header().Set("Content-Length", strconv.Itoa(len(content.body)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(content.body)
		}
	})
}

func (s *Store) subscription(ctx context.Context, token string, mihomo bool) (subscriptionContent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return subscriptionContent{}, err
	}
	if s.business == nil || s.business.material.Ownership == nil {
		return subscriptionContent{}, errSubscriptionMissing
	}
	m := s.business.material
	fingerprint := glivela.SubscriptionTokenFingerprint(token)
	var account *glivela.ImportAccount
	for i := range m.Plan.Accounts {
		item := &m.Plan.Accounts[i]
		if subtle.ConstantTimeCompare([]byte(fingerprint), []byte(item.SubscriptionTokenFingerprint)) == 1 && subtle.ConstantTimeCompare([]byte(token), []byte(m.SubscriptionTokens[item.Account.ID])) == 1 {
			account = item
		}
	}
	now := time.Now().UTC()
	if account == nil || !account.Account.Plan.Enabled || account.Account.Plan.ExpiryTime > 0 && account.Account.Plan.ExpiryTime <= now.UnixMilli() {
		return subscriptionContent{}, errSubscriptionMissing
	}
	quota, err := glivela.ProjectQuota(account.Account.Plan, account.Usage)
	if err != nil || !quota.Enabled {
		return subscriptionContent{}, errSubscriptionMissing
	}
	active := map[string]bool{}
	for _, gate := range quota.Gates {
		active[gate.CredentialID] = gate.Enabled
	}
	entries := []glivela.NativeEntry{}
	routes := []glivela.PublishedRoute{}
	links := map[string]string{}
	names := map[string]string{}
	byID := map[string]glivela.CredentialMaterial{}
	entryNodes := map[string]Node{}
	hiddenNative, publishedBases := map[string]bool{}, map[string]bool{}
	for _, grant := range account.Grants {
		if grant.Deployable() && grant.HideNative {
			hiddenNative[grant.Base.ID] = true
		}
	}
	for _, node := range s.nodes {
		if node.Desired.Entry != nil {
			entryNodes[node.ID] = node
		}
	}
	for _, credential := range account.Credentials {
		if !credential.Enabled || !active[credential.ID] {
			continue
		}
		entry, found := entryNodes[credential.EntryID]
		if !found || !runtimeFresh(entry, now) {
			continue
		}
		material := glivela.CredentialMaterial{Credential: credential, ProtocolID: m.ProtocolSecrets[credential.ID], HysteriaAuth: m.HysteriaSecrets[credential.ID], HysteriaIdentity: account.HysteriaIdentities[credential.ID]}
		if !slices.Contains(entry.Desired.Entry.Credentials, material) {
			continue
		}
		for _, endpoint := range m.Endpoints {
			if endpoint.Reality.EntryID != credential.EntryID || endpoint.LegacyRetired || !endpoint.QuotaAppliedEnabled || endpoint.TotalBytes > 0 && endpoint.UsedBytes >= endpoint.TotalBytes {
				continue
			}
			service := m.References.Services[endpoint.ServiceID]
			name := service.DisplayName
			if name == "" {
				name = service.Name
			}
			if name == "" {
				name = m.References.Applications[credential.EntryID].Name
			}
			if endpoint.VLESSEnabled && slices.ContainsFunc(entry.Desired.Entry.RealityEndpoints, func(current glivela.RealityEndpoint) bool { return reflect.DeepEqual(current, endpoint.Reality) }) {
				link, err := glivela.LinkForCredential(endpoint.Reality, material, name)
				if err != nil {
					return subscriptionContent{}, errSubscriptionUnverified
				}
				byID[credential.ID], links[credential.ID], names[credential.ID] = material, link, name
				if credential.Kind == glivela.NativeCredential {
					entries = append(entries, glivela.NativeEntry{Material: material, Protocol: glivela.VLESSReality, Link: link})
				}
			}
			if credential.Kind == glivela.NativeCredential && endpoint.HysteriaEnabled && endpoint.Hysteria != nil && slices.Contains(entry.Desired.Entry.HysteriaEndpoints, *endpoint.Hysteria) {
				expires, err := glivela.HysteriaCertificateNotAfter(*endpoint.Hysteria)
				if err != nil || !expires.After(now) {
					continue
				}
				link, err := glivela.Hysteria2LinkForCredential(*endpoint.Hysteria, material, name+" · HY2")
				if err != nil {
					return subscriptionContent{}, errSubscriptionUnverified
				}
				entries = append(entries, glivela.NativeEntry{Material: material, Protocol: glivela.Hysteria2, Link: link})
			}
		}
	}
	for _, grant := range account.Grants {
		base, baseOK := byID[grant.Base.ID]
		route, routeOK := byID[grant.Route.ID]
		entry, entryOK := entryNodes[grant.EntryID]
		if !baseOK || !routeOK || !entryOK || !grant.Deployable() || base.Credential != grant.Base || route.Credential != grant.Route {
			continue
		}
		if !slices.ContainsFunc(entry.Desired.Entry.Grants, func(current glivela.RouteGrant) bool { return sameGrantPolicy(current, grant) }) || !s.subscriptionPeerReady(entry, grant.EgressID, now) || grant.IPv4EgressID != "" && !s.subscriptionPeerReady(entry, grant.IPv4EgressID, now) {
			continue
		}
		grant.AppliedRev, grant.RuntimeGood = grant.DesiredRev, true
		published := glivela.PublishedRoute{Grant: grant, Protocol: glivela.VLESSReality, EntryName: names[grant.Base.ID], BaseLink: links[grant.Base.ID], RouteLink: links[grant.Route.ID], BaseProtocolIdentity: base.Credential.Identity, RouteProtocolIdentity: route.Credential.Identity}
		if selection := m.References.LandingSelection; selection != nil {
			published.EgressRegionPrefix = selection.LandingRegionCodes[grant.EgressID]
			published.IPv4EgressRegionPrefix = selection.LandingRegionCodes[grant.IPv4EgressID]
			published.EgressNameSuffix = selection.LandingNameSuffixes[grant.EgressID]
		}
		routes = append(routes, published)
		publishedBases[grant.Base.ID] = true
	}
	// An unavailable hidden-native route must not silently republish its
	// direct credential. Keep the base only when the renderer needs it to
	// construct an actually verified route (which then hides it normally).
	entries = slices.DeleteFunc(entries, func(entry glivela.NativeEntry) bool {
		return entry.Protocol == glivela.VLESSReality && hiddenNative[entry.Material.Credential.ID] && !publishedBases[entry.Material.Credential.ID]
	})
	if len(entries) == 0 {
		return subscriptionContent{}, errSubscriptionUnverified
	}
	result := subscriptionContent{contentType: "text/plain; charset=utf-8", userInfo: "upload=0; download=" + strconv.FormatInt(quota.UsedBytes, 10) + "; total=" + strconv.FormatInt(account.Account.Plan.TotalBytes, 10)}
	if account.Account.Plan.ExpiryTime > 0 {
		result.userInfo += "; expire=" + strconv.FormatInt(account.Account.Plan.ExpiryTime/1000, 10)
	}
	if mihomo {
		result.body, err = glivela.RenderMihomo(entries, account.Account.ID, glivela.FixedMode, routes)
		result.contentType = "application/yaml; charset=utf-8"
	} else {
		result.body, err = glivela.RenderLinks(entries, account.Account.ID, glivela.FixedMode, routes, true)
	}
	if err != nil {
		return subscriptionContent{}, errSubscriptionUnverified
	}
	return result, nil
}

func sameGrantPolicy(a, b glivela.RouteGrant) bool {
	a.AppliedRev, b.AppliedRev = 0, 0
	a.RuntimeGood, b.RuntimeGood = false, false
	return a == b
}

// Publication checks only this entry's route, not unrelated entries which
// happen to share the same landing. A verifier-only legacy identity cannot
// authorize the new owned subscription.
func (s *Store) subscriptionPeerReady(entry Node, landingID string, now time.Time) bool {
	for _, node := range s.nodes {
		if node.ID != landingID || !runtimeFresh(node, now) || !entryPeerFresh(entry, node, now) {
			continue
		}
		authorized, ok := node.RouteEntries[entry.ID]
		check, hasCheck := node.Checks[entry.ID]
		if !ok || !hasCheck || s.nodes[authorized.CertificateID].ID != entry.ID || check.CertificateID != authorized.CertificateID || check.Request.SnapshotID != s.business.snapshotID || !routeTargetsLanding(check.Request, node) || !entryRouteMatches(entry, check.Request) || check.Result == nil || validateRouteResult(check.Request, *check.Result) != nil || !check.Result.Passed || check.ReceivedAt.IsZero() || check.ReceivedAt.After(now) || now.Sub(check.ReceivedAt) > 5*time.Minute {
			return false
		}
		return true
	}
	return false
}
