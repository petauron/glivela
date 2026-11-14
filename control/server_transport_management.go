package control

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

type ServerTransportChange struct {
	Resource         glivela.ServerTransport `json:"resource"`
	ExpectedRevision uint64                  `json:"expectedRevision,string"`
	Delete           bool                    `json:"delete,omitempty"`
}

type ServerTransportView struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	AccountID string   `json:"accountId"`
	EntryID   string   `json:"entryId"`
	EgressID  string   `json:"egressId"`
	RelayID   string   `json:"relayId,omitempty"`
	Port      int      `json:"port"`
	RouteIDs  []string `json:"routeIds"`
}

// Claim only an already-applied, exact listener. This endpoint never creates
// sockets, widens sources, returns keys, or reads a client publication record.
func (s *Store) ChangeServerTransport(ctx context.Context, c ServerTransportChange) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bad := errors.New("control: server transport ownership change refused")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.business == nil || s.business.faulted || s.business.material.Ownership == nil || c.ExpectedRevision == 0 || c.ExpectedRevision == math.MaxUint64 || c.Resource.Validate() != nil {
		return bad
	}
	next := s.business.material
	ai := slices.IndexFunc(next.Plan.Accounts, func(a glivela.ImportAccount) bool { return a.Account.ID == c.Resource.AccountID })
	if ai < 0 {
		return bad
	}
	old, exists := next.ServerTransports[c.Resource.ID]
	if c.Delete && (!exists || !reflect.DeepEqual(old, c.Resource)) {
		return bad
	}
	if exists {
		a, b := old, c.Resource
		a.Name, b.Name = "", ""
		if !reflect.DeepEqual(a, b) {
			return bad
		}
	}
	if next.Plan.Accounts[ai].Account.DesiredRevision != c.ExpectedRevision {
		return bad
	}
	if c.Delete {
		ids := []string{old.EntryID, old.EgressID}
		if old.Peer.Relay != nil {
			ids = append(ids, old.Peer.Relay.NodeID)
		}
		for _, id := range ids {
			fresh := false
			for _, node := range s.nodes {
				if node.ID == id && runtimeFresh(node, time.Now()) {
					fresh = true
				}
			}
			if !fresh {
				return bad
			}
		}
		for _, account := range next.Plan.Accounts {
			for _, g := range account.Grants {
				if !next.DeletedRoutes[g.ID] && g.EntryID == old.EntryID && g.EgressID == old.EgressID && g.ClientChainID == old.Peer.ClientChainID {
					return bad
				}
			}
		}
		for _, node := range s.nodes {
			if node.Desired.Entry != nil && slices.ContainsFunc(node.Desired.Entry.Peers, func(p glivela.RoutePeer) bool { return p.Transport.ClientListenerID == old.ID }) {
				return bad
			}
			if node.Desired.Landing != nil && slices.ContainsFunc(node.Desired.Landing.ClientListeners, func(l glivela.TransportListener) bool { return l.ID == old.ID }) {
				return bad
			}
		}
	} else {
		var entry, target Node
		for _, n := range s.nodes {
			if n.ID == c.Resource.EntryID {
				entry = n
			}
			if n.ID == c.Resource.EgressID {
				target = n
			}
		}
		if _, ok := serverTransportIdentity(s.nodes, c.Resource, entry, target, c.Resource.Peer); !ok || !runtimeFresh(entry, time.Now()) || !runtimeFresh(target, time.Now()) || !slices.Contains(target.Desired.Landing.ClientListeners, c.Resource.Listener) {
			return bad
		}
		if c.Resource.Peer.Relay != nil {
			found := false
			for _, n := range s.nodes {
				if n.ID == c.Resource.Peer.Relay.NodeID && runtimeFresh(n, time.Now()) && n.Desired.Landing != nil && slices.Contains(n.Desired.Landing.ClientListeners, *c.Resource.RelayListener) {
					found = true
				}
			}
			if !found {
				return bad
			}
		}
	}
	if exists && !c.Delete && reflect.DeepEqual(old, c.Resource) {
		return nil
	}
	// Detach caller-owned pointer fields before persisting the resource.
	raw, err := json.Marshal(c.Resource)
	if err != nil {
		return bad
	}
	var owned glivela.ServerTransport
	if json.Unmarshal(raw, &owned) != nil {
		return bad
	}
	c.Resource = owned
	next.ServerTransports = maps.Clone(next.ServerTransports)
	if next.ServerTransports == nil {
		next.ServerTransports = map[string]glivela.ServerTransport{}
	}
	if c.Delete {
		delete(next.ServerTransports, c.Resource.ID)
	} else {
		next.ServerTransports[c.Resource.ID] = c.Resource
	}
	accounts := slices.Clone(next.Plan.Accounts)
	accounts[ai].Account.DesiredRevision++
	next.Plan, err = glivela.PlanImport(accounts)
	if err != nil {
		return err
	}
	return s.saveOwnedBusinessLocked(next)
}
