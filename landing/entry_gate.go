package landing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// TrafficGate fences one managed proxy runtime's traffic to one landing SOCKS
// listener. Host sockets use a dedicated group; retained bridge runtimes use
// their bridge interface. Glivela probes remain independent. Install must be called by
// a boot prerequisite before Docker can restore a saved landing route. This
// type does not install that prerequisite itself.
type TrafficGate struct {
	mu       sync.Mutex
	peer     PeerIdentity
	bridge   string
	gid      uint32
	revision uint64
	table    string
	marker   string
	run      func(context.Context, []byte, ...string) ([]byte, error)
}

func NewBridgeGate(peer PeerIdentity, bridge string, revision uint64) (*TrafficGate, error) {
	if peer.Validate() != nil || !bridgeNamePattern.MatchString(bridge) || revision == 0 {
		return nil, errors.New("landing: invalid bridge gate identity")
	}
	return newTrafficGate(peer, bridge, revision)
}

func newTrafficGate(peer PeerIdentity, bridge string, revision uint64) (*TrafficGate, error) {
	identity, _ := json.Marshal(struct {
		Peer     PeerIdentity
		Bridge   string
		Revision uint64
	}{peer, bridge, revision})
	hash := sha256.Sum256(identity)
	return &TrafficGate{peer: peer, bridge: bridge, revision: revision,
		table:  "glivela_entry_peer_" + hex.EncodeToString(hash[:12]),
		marker: "glivela-entry-peer-v1:" + hex.EncodeToString(hash[:]), run: runNFT}, nil
}

// No packet-path update statement is emitted: traffic cannot refresh its own
// permission. A persistent kernel set expires even if Glivela is killed.
func (g *TrafficGate) objects() []map[string]nftObject {
	if g.gid != 0 {
		return g.hostObjects()
	}
	objects := []map[string]nftObject{
		{"table": {"family": "inet", "name": g.table, "comment": g.marker}},
		{"set": {"family": "inet", "table": g.table, "name": "allowed", "type": "ipv4_addr", "flags": []string{"timeout"}, "timeout": int(AllowLifetime / time.Second), "size": 1}},
		{"chain": {"family": "inet", "table": g.table, "name": "forward", "type": "filter", "hook": "forward", "prio": -300, "policy": "accept"}},
		{"chain": {"family": "inet", "table": g.table, "name": "outbound"}},
		{"chain": {"family": "inet", "table": g.table, "name": "inbound"}},
	}
	match := func(left, right any) any {
		return nftObject{"match": nftObject{"op": "==", "left": left, "right": right}}
	}
	payload := func(protocol, field string) any {
		return nftObject{"payload": nftObject{"protocol": protocol, "field": field}}
	}
	meta := func(key string) any { return nftObject{"meta": nftObject{"key": key}} }
	rule := func(chain string, expr ...any) {
		objects = append(objects, map[string]nftObject{"rule": {"family": "inet", "table": g.table, "chain": chain, "expr": expr}})
	}
	// Named payload protocols make nft generate the required family/transport
	// dependencies. Its JSON read-back omits redundant explicit meta checks;
	// emit the canonical form instead of weakening ownership comparison.
	for _, protocol := range []string{"tcp", "udp"} {
		outbound := []any{match(meta("iifname"), g.bridge), match(payload("ip", "daddr"), g.peer.Address)}
		inbound := []any{match(meta("oifname"), g.bridge), match(payload("ip", "saddr"), g.peer.Address)}
		if protocol == "tcp" {
			outbound = append(outbound, match(payload("tcp", "dport"), SOCKSPort))
			inbound = append(inbound, match(payload("tcp", "sport"), SOCKSPort))
		} else {
			// Xray's UDP relay ports are per-association, not Dante's fixed range.
			outbound = append(outbound, match(meta("l4proto"), "udp"))
			inbound = append(inbound, match(meta("l4proto"), "udp"))
		}
		rule("forward", append(outbound, nftObject{"jump": nftObject{"target": "outbound"}})...)
		rule("forward", append(inbound, nftObject{"jump": nftObject{"target": "inbound"}})...)
	}
	rule("outbound", match(payload("ip", "daddr"), "@allowed"), nftObject{"return": nil})
	rule("outbound", nftObject{"drop": nil})
	rule("inbound", match(payload("ip", "saddr"), "@allowed"), nftObject{"return": nil})
	rule("inbound", nftObject{"drop": nil})
	return objects
}

// Install is idempotent and always starts closed. It never replaces a table
// with different ownership or policy. A changed revision needs its own gate;
// the route switcher must keep the old gate until old connections are stopped.
func (g *TrafficGate) Install(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	document, err := g.snapshot(ctx)
	if err != nil {
		return err
	}
	found, err := g.validate(document)
	if err != nil {
		return err
	}
	if !found {
		commands := make([]any, 0, len(g.objects()))
		for _, object := range g.objects() {
			commands = append(commands, nftObject{"create": object})
		}
		// Rules support add, not create. Table creation still fails on collision
		// and the complete transaction is atomic.
		for i, object := range g.objects() {
			if _, ok := object["rule"]; ok {
				commands[i] = nftObject{"add": object}
			}
		}
		applyErr := g.apply(ctx, commands)
		document, err = g.snapshot(ctx)
		if err != nil {
			return errors.Join(applyErr, err)
		}
		found, err = g.validate(document)
		if err != nil || !found {
			return errors.Join(applyErr, err, errors.New("landing: gate installation was not confirmed"))
		}
	}
	return g.block(ctx)
}

func (g *TrafficGate) Block(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.block(ctx)
}

// Verify is observational. It never installs/repairs a missing policy or
// extends a lease based on a process/configuration health poll.
func (g *TrafficGate) Verify(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	document, err := g.snapshot(ctx)
	if err != nil {
		return err
	}
	if found, err := g.validate(document); err != nil || !found {
		return errors.Join(err, errors.New("landing: entry gate missing or changed"))
	}
	return nil
}

// Remove is used only after restoring the direct configuration or replacing
// this revision with another closed gate. Refuse foreign or still-open rules.
func (g *TrafficGate) Remove(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	document, err := g.snapshot(ctx)
	if err != nil {
		return err
	}
	found, err := g.validate(document)
	if err != nil || !found {
		return err
	}
	if len(g.elements(document)) != 0 {
		return errors.New("landing: close the gate before removal")
	}
	removeErr := g.apply(ctx, []any{nftObject{"delete": nftObject{"table": nftObject{"family": "inet", "name": g.table}}}})
	document, err = g.snapshot(ctx)
	if err != nil {
		return errors.Join(removeErr, err)
	}
	found, err = g.validate(document)
	if err != nil || found {
		return errors.Join(removeErr, err, errors.New("landing: gate removal was not confirmed"))
	}
	return nil
}

// A closed gate from an earlier revision still runs as a separate nft forward
// base chain. It drops container packets even when the current gate has a live
// lease. Remove only closed tables with the exact managed policy for this peer
// address and bridge; the current gate remains the traffic authority.
func (g *TrafficGate) RemoveClosedConflicts(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	document, err := g.snapshot(ctx)
	if err != nil {
		return err
	}
	if found, err := g.validate(document); err != nil || !found {
		return errors.Join(err, errors.New("landing: current gate is unavailable"))
	}
	conflicts := []*TrafficGate{}
	for _, object := range document.Objects {
		table := object["table"]
		if table == nil || table["family"] != "inet" {
			continue
		}
		name, _ := table["name"].(string)
		if name == g.table || !strings.HasPrefix(name, g.tablePrefix()) || !g.matchesTarget(document, name) {
			continue
		}
		marker, _ := table["comment"].(string)
		if !g.validOwnership(name, marker) {
			return errors.New("landing: conflicting gate ownership is unavailable")
		}
		candidate := &TrafficGate{peer: g.peer, bridge: g.bridge, gid: g.gid, revision: g.revision, table: name, marker: marker, run: g.run}
		if found, err := candidate.validate(document); err != nil || !found || len(candidate.elements(document)) != 0 {
			return errors.Join(err, errors.New("landing: conflicting gate is not a closed managed policy"))
		}
		conflicts = append(conflicts, candidate)
	}
	if len(conflicts) == 0 {
		return nil
	}
	commands := make([]any, 0, len(conflicts))
	for _, candidate := range conflicts {
		commands = append(commands, nftObject{"delete": nftObject{"table": nftObject{"family": "inet", "name": candidate.table}}})
	}
	applyErr := g.apply(ctx, commands)
	document, err = g.snapshot(ctx)
	if err != nil {
		return errors.Join(applyErr, err)
	}
	if found, err := g.validate(document); err != nil || !found {
		return errors.Join(applyErr, err, errors.New("landing: current gate changed during conflict cleanup"))
	}
	for _, candidate := range conflicts {
		if found, err := candidate.validate(document); err != nil || found {
			return errors.Join(applyErr, err, errors.New("landing: conflicting gate removal was not confirmed"))
		}
	}
	return nil // A lost command response is harmless after confirming all removals.
}

func (g *TrafficGate) matchesTarget(document nftDocument, table string) bool {
	for _, object := range document.Objects {
		rule := object["rule"]
		if rule == nil || rule["family"] != "inet" || rule["table"] != table || rule["chain"] != g.scopeChain() {
			continue
		}
		bridge, address := false, false
		expressions, ok := rule["expr"].([]any)
		if !ok {
			continue
		}
		for _, expression := range expressions {
			item, ok := expression.(map[string]any)
			if !ok {
				continue
			}
			match, ok := item["match"].(map[string]any)
			if !ok || match["op"] != "==" {
				continue
			}
			left, ok := match["left"].(map[string]any)
			if !ok {
				continue
			}
			if meta, ok := left["meta"].(map[string]any); ok && (g.gid == 0 && meta["key"] == "iifname" && match["right"] == g.bridge || g.gid != 0 && meta["key"] == "skgid" && match["right"] == float64(g.gid)) {
				bridge = true
			}
			if payload, ok := left["payload"].(map[string]any); ok && payload["protocol"] == "ip" && payload["field"] == "daddr" && match["right"] == g.peer.Address {
				address = true
			}
		}
		if bridge && address {
			return true
		}
	}
	return false
}

func (g *TrafficGate) block(ctx context.Context) error {
	document, err := g.snapshot(ctx)
	if err != nil {
		return err
	}
	if found, err := g.validate(document); err != nil || !found {
		return errors.Join(err, errors.New("landing: gate policy is unavailable"))
	}
	applyErr := g.apply(ctx, []any{g.flushAllowed()})
	document, err = g.snapshot(ctx)
	if err != nil {
		return errors.Join(applyErr, err)
	}
	if found, err := g.validate(document); err != nil || !found || len(g.elements(document)) != 0 {
		return errors.Join(applyErr, err, errors.New("landing: business blocking was not confirmed"))
	}
	return nil // Includes a lost command response followed by confirmed closure.
}

// Renew is internal to Monitor: callers cannot open the gate based on a UI
// flag, a historical ping, or a health result for an earlier revision.
func (g *TrafficGate) renew(ctx context.Context, until time.Time) (time.Time, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	document, err := g.snapshot(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if found, err := g.validate(document); err != nil || !found {
		return time.Time{}, errors.Join(err, errors.New("landing: gate policy is unavailable"))
	}
	remaining := time.Until(until)
	if remaining <= nftTimeout+time.Second || remaining > AllowLifetime {
		return time.Time{}, errors.New("landing: gate proof expired")
	}
	// libnftables JSON timeouts are seconds. Reserve the command deadline so
	// a delayed apply cannot extend the original proof's validity.
	seconds := int((remaining - nftTimeout) / time.Second)
	element := nftObject{"family": "inet", "table": g.table, "name": "allowed", "elem": []any{nftObject{"elem": nftObject{"val": g.peer.Address, "timeout": seconds}}}}
	applyErr := g.apply(ctx, []any{g.flushAllowed(), nftObject{"add": nftObject{"element": element}}})
	observedStart := time.Now()
	document, err = g.snapshot(ctx)
	if err != nil {
		return time.Time{}, errors.Join(applyErr, err)
	}
	if found, err := g.validate(document); err != nil || !found || !g.hasLiveLease(document, until) {
		return time.Time{}, errors.Join(applyErr, err, errors.New("landing: gate permission was not confirmed"))
	}
	// expires is sampled by nft after observedStart. Starting the reported
	// remaining duration at the earlier query start cannot overstate the
	// actual installed lease, unlike reporting the original proof deadline.
	lease := g.elements(document)[0].(map[string]any)["elem"].(map[string]any)
	expires := lease["expires"].(float64)
	confirmed := observedStart.Add(time.Duration(expires * float64(time.Second)))
	if confirmed.After(until) {
		confirmed = until
	}
	if !confirmed.After(time.Now()) {
		return time.Time{}, errors.New("landing: confirmed gate lease expired")
	}
	return confirmed, nil
}

func (g *TrafficGate) flushAllowed() any {
	return nftObject{"flush": nftObject{"set": nftObject{"family": "inet", "table": g.table, "name": "allowed"}}}
}

func (g *TrafficGate) apply(ctx context.Context, commands []any) error {
	data, err := json.Marshal(nftObject{"nftables": commands})
	if err != nil {
		return errors.New("landing: invalid firewall transaction")
	}
	_, err = g.run(ctx, data, "--json", "--file", "-")
	return err
}

func (g *TrafficGate) snapshot(ctx context.Context) (nftDocument, error) {
	data, err := g.run(ctx, nil, "--json", "list", "ruleset")
	var document nftDocument
	if err != nil {
		return document, err
	}
	// A empty/missing root is not proof that a policy exists.
	if len(data) > nftOutputLimit || json.Unmarshal(data, &document) != nil || document.Objects == nil {
		return document, errors.New("landing: invalid firewall state")
	}
	return document, nil
}

func (g *TrafficGate) validate(document nftDocument) (bool, error) {
	return validateNFTPolicy(document, g.table, g.objects(), true)
}

func (g *TrafficGate) elements(document nftDocument) []any {
	for _, object := range document.Objects {
		if set := object["set"]; set != nil && set["family"] == "inet" && set["table"] == g.table && set["name"] == "allowed" {
			if set["elem"] == nil {
				return nil
			}
			if elements, ok := set["elem"].([]any); ok {
				return elements
			}
			return []any{set["elem"]}
		}
	}
	return nil
}

func (g *TrafficGate) hasLiveLease(document nftDocument, until time.Time) bool {
	elements := g.elements(document)
	if len(elements) != 1 || !time.Now().Before(until) {
		return false
	}
	wrapper, ok := elements[0].(map[string]any)
	if !ok {
		return false
	}
	element, ok := wrapper["elem"].(map[string]any)
	if !ok || element["val"] != g.peer.Address {
		return false
	}
	timeout, _ := element["timeout"].(float64)
	expires, _ := element["expires"].(float64)
	return timeout > 0 && timeout <= AllowLifetime.Seconds() && expires > 0 && expires <= timeout && expires <= time.Until(until).Seconds()
}
