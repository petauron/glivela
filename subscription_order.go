package glivela

import (
	"errors"
	"strings"
)

// SubscriptionOrder is presentation-only account data in the encrypted business
// source. Its revision is independent of node configurations and traffic.
type SubscriptionOrder struct {
	Revision uint64   `json:"revision,string"`
	IDs      []string `json:"ids"`
}

func (o SubscriptionOrder) Validate() error {
	if o.Revision == 0 || len(o.IDs) > 4096 {
		return errors.New("glivela: invalid subscription order")
	}
	seen := map[string]bool{}
	for _, id := range o.IDs {
		parts := strings.Split(id, "/")
		valid := len(parts) == 2 && (parts[0] == "route" || parts[0] == "chain") && ValidIdentifier(parts[1]) || len(parts) == 3 && parts[0] == "native" && ProtocolKind(parts[1]).Valid() && ValidIdentifier(parts[2])
		if !valid || seen[id] {
			return errors.New("glivela: invalid subscription order item")
		}
		seen[id] = true
	}
	return nil
}

type subscriptionRank map[string]int

func subscriptionRanks(ids []string, entries []resolvedSubscriptionEntry) subscriptionRank {
	ranks := make(subscriptionRank, len(ids))
	for index, id := range ids {
		ranks[id] = 2 * index
	}
	if len(ids) == 0 {
		return ranks
	}
	// Leave gaps between saved ranks so new native proxies can follow the last
	// visible saved native without reordering any saved routes or chains.
	// With no visible saved native, place new natives before the saved items.
	position := -1
	for _, entry := range entries {
		if rank, saved := ranks[entry.ID]; entry.Kind == "native" && saved {
			position = max(position, rank+1)
		}
	}
	for _, entry := range entries {
		if _, saved := ranks[entry.ID]; entry.Kind == "native" && !saved {
			ranks[entry.ID] = position
		}
	}
	return ranks
}

func (r subscriptionRank) position(id string) int {
	if position, exists := r[id]; exists {
		return position
	}
	return 2 * len(r)
}
