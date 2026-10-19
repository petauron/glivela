package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

type routeRepository interface {
	RouteExchange(context.Context, string, *RouteProbeResult) ([]RouteProbe, error)
}
type routeExchange struct {
	Report *RouteProbeResult `json:"report,omitempty"`
}
type routeAssignments struct {
	Checks []RouteProbe `json:"checks"`
}

// Called only after Handler verifies the TLS peer. Node-provided identities
// cannot authorize a report; assignment binds the exact certificate instead.
func handleRouteExchange(repository Repository, w http.ResponseWriter, r *http.Request) {
	routes, ok := repository.(routeRepository)
	if !ok {
		http.Error(w, "unsupported request", http.StatusNotFound)
		return
	}
	var request routeExchange
	if decode(http.MaxBytesReader(w, r.Body, 16<<10), &request) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	checks, err := routes.RouteExchange(r.Context(), CertificateID(r.TLS.PeerCertificates[0]), request.Report)
	if err != nil {
		http.Error(w, "route exchange refused", http.StatusForbidden)
		return
	}
	if checks == nil {
		checks = []RouteProbe{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(routeAssignments{Checks: checks})
}

func (c *Client) RouteExchange(ctx context.Context, report *RouteProbeResult) ([]RouteProbe, error) {
	endpoint, err := url.Parse(c.endpoint)
	if err != nil {
		return nil, errors.New("control: invalid endpoint")
	}
	endpoint.Path = "/v1/route-checks"
	raw, err := json.Marshal(routeExchange{Report: report})
	if err != nil {
		return nil, errors.New("control: invalid route report")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("control: invalid route request")
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("control: route exchange failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("control: route exchange refused")
	}
	var result routeAssignments
	if decode(io.LimitReader(response.Body, maxMessage+1), &result) != nil {
		return nil, errors.New("control: invalid route assignments")
	}
	for _, p := range result.Checks {
		if p.Validate() != nil {
			return nil, errors.New("control: invalid route assignment")
		}
	}
	return result.Checks, nil
}
