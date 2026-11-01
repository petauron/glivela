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

func subscriptionRanks(ids []string) subscriptionRank {
	ranks := make(subscriptionRank, len(ids))
	for index, id := range ids {
		ranks[id] = index
	}
	return ranks
}

func (r subscriptionRank) position(id string) int {
	if position, exists := r[id]; exists {
		return position
	}
	return len(r)
}
