package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"slices"

	glivela "github.com/petauron/glivela"
)

type SubscriptionOrderChange struct {
	AccountID        string    `json:"accountId"`
	ExpectedRevision *uint64   `json:"expectedRevision,string,omitempty"`
	Inventory        string    `json:"inventory,omitempty"`
	IDs              *[]string `json:"ids,omitempty"`
}

type SubscriptionOrderView struct {
	Revision  uint64                     `json:"revision,string"`
	Inventory string                     `json:"inventory"`
	Available bool                       `json:"available"`
	Items     []glivela.SubscriptionItem `json:"items"`
}

func subscriptionOrderView(order glivela.SubscriptionOrder, content subscriptionContent) SubscriptionOrderView {
	items := content.items
	if items == nil {
		items = []glivela.SubscriptionItem{}
	}
	raw, _ := json.Marshal(items)
	sum := sha256.Sum256(raw)
	return SubscriptionOrderView{Revision: order.Revision, Inventory: hex.EncodeToString(sum[:]), Available: len(items) > 0, Items: items}
}

// ChangeSubscriptionOrder never projects node state or advances account policy.
// The visible inventory fingerprint prevents saving an outdated list, while
// non-publishable retained IDs keep their slots instead of being re-enabled.
func (s *Store) ChangeSubscriptionOrder(ctx context.Context, change SubscriptionOrderChange) (SubscriptionOrderView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := errors.New("control: subscription order changed; reload the actual inventory")
	if ctx.Err() != nil {
		return SubscriptionOrderView{}, ctx.Err()
	}
	if !glivela.ValidIdentifier(change.AccountID) || s.business == nil || s.business.faulted || s.business.material.Ownership == nil || (change.IDs == nil) != (change.ExpectedRevision == nil) {
		return SubscriptionOrderView{}, invalid
	}
	if !slices.ContainsFunc(s.business.material.Plan.Accounts, func(a glivela.ImportAccount) bool { return a.Account.ID == change.AccountID }) {
		return SubscriptionOrderView{}, invalid
	}
	order := s.business.material.SubscriptionOrders[change.AccountID]
	content, err := s.subscriptionAccountLocked(ctx, change.AccountID, true)
	if err != nil {
		if change.IDs == nil && (errors.Is(err, errSubscriptionMissing) || errors.Is(err, errSubscriptionUnverified)) {
			return subscriptionOrderView(order, subscriptionContent{}), nil
		}
		return SubscriptionOrderView{}, invalid
	}
	view := subscriptionOrderView(order, content)
	if change.IDs == nil {
		return view, nil
	}
	ids := *change.IDs
	if !view.Available || *change.ExpectedRevision != order.Revision || change.Inventory != view.Inventory || len(ids) != len(view.Items) || len(ids) > 4096 {
		return SubscriptionOrderView{}, invalid
	}
	visible := make(map[string]bool, len(view.Items))
	for _, item := range view.Items {
		visible[item.ID] = true
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !visible[id] || seen[id] {
			return SubscriptionOrderView{}, invalid
		}
		seen[id] = true
	}
	merged := make([]string, 0, len(order.IDs)+len(ids))
	nextVisible := 0
	for _, id := range order.IDs {
		if visible[id] {
			merged = append(merged, ids[nextVisible])
			nextVisible++
		} else {
			merged = append(merged, id)
		}
	}
	merged = append(merged, ids[nextVisible:]...)
	if !slices.Equal(merged, order.IDs) {
		if order.Revision == math.MaxUint64 {
			return SubscriptionOrderView{}, invalid
		}
		next := s.business.material
		next.SubscriptionOrders = maps.Clone(next.SubscriptionOrders)
		if next.SubscriptionOrders == nil {
			next.SubscriptionOrders = map[string]glivela.SubscriptionOrder{}
		}
		order = glivela.SubscriptionOrder{Revision: order.Revision + 1, IDs: merged}
		if order.Validate() != nil {
			return SubscriptionOrderView{}, invalid
		}
		next.SubscriptionOrders[change.AccountID] = order
		if err := s.saveOwnedBusinessLocked(next); err != nil {
			return SubscriptionOrderView{}, err
		}
	}
	content, err = s.subscriptionAccountLocked(ctx, change.AccountID, true)
	if err != nil {
		return SubscriptionOrderView{}, err
	}
	return subscriptionOrderView(order, content), nil
}
