package control

import (
	"context"
	"errors"
	"net/url"
	"strings"

	glivela "github.com/petauron/glivela"
)

// The externally published origin is application configuration, not guessed
// from the private listener, a request Host header or a platform session.
func (s *Store) ConfigureSubscriptionOrigin(origin string) error {
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Path != "" && u.Path != "/" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(origin) > 2048 || strings.ContainsAny(origin, "\r\n\\") {
			return errors.New("control: exact published HTTPS subscription origin required")
		}
		origin = "https://" + u.Host
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscriptionOrigin = origin
	return nil
}

// Explicit administrator-only disclosure. Inventory responses still contain
// no subscription tokens, and download/route acceptance remains independent.
func (s *Store) SubscriptionURL(ctx context.Context, account string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !glivela.ValidIdentifier(account) || s.business == nil || s.business.faulted || s.business.material.Ownership == nil || s.subscriptionOrigin == "" {
		return "", errors.New("control: owned account and configured published subscription origin required")
	}
	token := s.business.material.SubscriptionTokens[account]
	if token == "" {
		return "", errors.New("control: subscription identity unavailable")
	}
	return s.subscriptionOrigin + "/sub/" + url.PathEscape(token), nil
}
