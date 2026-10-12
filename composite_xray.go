package meridian

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

const runtimeFileDirectory = "/etc/vastora"

func compositeRuntimeFiles(plan XrayPlan) (map[string][]byte, error) {
	if !slices.ContainsFunc(plan.Grants, func(g RouteGrant) bool { return g.IPv4EgressID != "" }) {
		return nil, nil
	}
	projection, err := prepareXrayProjection(plan)
	if err != nil {
		return nil, err
	}
	return compositeRuntimeFilesWithoutProjection(plan, projection)
}

func runtimeFileName(kind string, contents []byte) string {
	digest := sha256.Sum256(contents)
	return "glivela-" + kind + "-" + hex.EncodeToString(digest[:]) + ".lua"
}

func projectCompositeRuntime(plan XrayPlan, projection xrayProjection, config map[string]any) error {
	files, err := compositeRuntimeFilesWithoutProjection(plan, projection)
	if err != nil || len(files) == 0 {
		return err
	}
	var routingPath string
	for name := range files {
		routingPath = path.Join(runtimeFileDirectory, name)
	}
	outbounds := config["outbounds"].([]any)
	// Script errors in Xray fall through to its first outbound. Keep this
	// blocked and explicitly select native credentials in the script.
	outbounds = append([]any{map[string]any{"protocol": "blackhole", "tag": "composite-default-deny"}}, outbounds...)
	for _, grant := range projection.grants {
		if grant.IPv4EgressID == "" {
			continue
		}
		peer := projection.peers[grant.IPv4EgressID]
		tag := routeOutboundTag(grant.ID)
		outbounds = append(outbounds,
			map[string]any{"protocol": "socks", "tag": tag + "-ipv4", "settings": map[string]any{"servers": []any{map[string]any{"address": peer.Address, "port": peer.Port}}}},
		)
	}
	config["outbounds"] = outbounds
	config["routing"] = map[string]any{"domainStrategy": "AsIs", "script": routingPath}
	config["dns"] = map[string]any{
		"queryStrategy": "UseIP",
		"servers": []any{
			map[string]any{"id": "native", "address": "localhost"},
			// Only the routing script explicitly queries this server. Ordinary
			// native/fixed lookups retain their pre-existing system resolver.
			map[string]any{"id": "composite", "address": "tcp+local://" + CompositeDNSAddress, "timeoutMs": 5000, "disableCache": true, "skipFallback": true},
		},
	}
	return nil
}

func compositeRuntimeFilesWithoutProjection(plan XrayPlan, projection xrayProjection) (map[string][]byte, error) {
	if !slices.ContainsFunc(plan.Grants, func(g RouteGrant) bool { return g.IPv4EgressID != "" }) {
		return nil, nil
	}
	routing := []byte(compositeRoutingScript(projection))
	return map[string][]byte{runtimeFileName("routing", routing): routing}, nil
}

// Decimal byte escapes work for every accepted user label, including Unicode,
// without allowing a persisted label to inject executable Lua.
func luaString(value string) string {
	var result strings.Builder
	result.WriteByte('"')
	for _, b := range []byte(value) {
		fmt.Fprintf(&result, "\\%03d", b)
	}
	result.WriteByte('"')
	return result.String()
}

func compositeRoutingScript(projection xrayProjection) string {
	var script strings.Builder
	script.WriteString("local router = require('xray.router')\nassert(router.TargetSelectionRevision == 1, 'glivela target selection runtime is required')\nlocal dns = require('xray.dns')\nassert(dns.IsNoData, 'glivela DNS evidence runtime is required')\nlocal business_dns\nfor _, server in ipairs(dns.Servers) do if server.ID == 'composite' then business_dns = server end end\nassert(business_dns, 'managed composite DNS is required')\nlocal geo = require('xray.geodata')\nlocal log = require('xray.log')\nlocal blocked = geo.BuildIPMatcher(")
	for i, cidr := range compositeBlockedCIDRs {
		if i > 0 {
			script.WriteByte(',')
		}
		script.WriteString(luaString(cidr))
	}
	script.WriteString(")\nlocal v4 = geo.BuildIPMatcher('0.0.0.0/0')\nlocal v6 = geo.BuildIPMatcher('::/0')\nlocal denied_ports = {\n")
	for _, port := range compositeBlockedPorts {
		fmt.Fprintf(&script, "[%d]=true,", port)
	}
	script.WriteString("}\nlocal native = {}\nlocal hysteria = {}\nlocal routes = {}\n")
	for _, endpoint := range projection.realityEndpoints {
		for _, material := range projection.credentials[endpoint.EntryID] {
			if material.Credential.Kind == NativeCredential {
				fmt.Fprintf(&script, "native[%s] = native[%s] or {}; native[%s][%s]=true\n", luaString(endpoint.InboundTag), luaString(endpoint.InboundTag), luaString(endpoint.InboundTag), luaString(material.Credential.User))
			}
		}
	}
	for _, endpoint := range projection.hysteriaEndpoints {
		// Hysteria UDP does not reliably expose the authenticated email to the
		// router. Its inbound contains native credentials only; routed
		// credentials never have Hysteria auth material and cannot enter here.
		fmt.Fprintf(&script, "hysteria[%s]=true\n", luaString(endpoint.InboundTag))
	}
	for _, grant := range projection.grants {
		tag := routeOutboundTag(grant.ID)
		fmt.Fprintf(&script, "routes[%s]={inbound=%s, ipv6=%s, ipv4=%s, composite=%t}\n", luaString(grant.Route.User), luaString(grant.InboundTag), luaString(tag), luaString(tag+"-ipv4"), grant.IPv4EgressID != "")
	}
	script.WriteString(`
local function deny(reason)
    log.Warning("glivela selection failed stage=routing reason=", reason)
    return "blocked", "glivela_" .. reason
end
local function selected(outbound, family, reason)
    -- Existing core log-level controls apply. No user, hostname, credential,
    -- or subscription URL is included in this diagnostic record.
    log.Info("glivela selection stage=routing outbound=", outbound, " family=", family, " reason=", reason)
    return outbound, "glivela_" .. family .. "_" .. reason
end
function HandleRoute(ctx, inbound, sourcePort, port, localPort, domain, network, protocol, user)
    if inbound == "api" then return "api", "glivela_api" end
    if hysteria[inbound] then return "direct", "glivela_native_hysteria" end
    local route = routes[user]
    if route then
        if network ~= router.NetworkTCP then return deny("tcp_only") end
        if not route.composite then
            if inbound == route.inbound then return route.ipv6, "glivela_fixed" end
            return deny("credential_scope")
        end
        if denied_ports[port] then return deny("management_port") end
        if inbound ~= route.inbound then return deny("credential_scope") end
        -- Original literals win over sniffed HTTP Host/TLS SNI. A Fake-IP
        -- cannot become a destination just because arbitrary payload names it.
        local ips = ctx:GetOriginalTargetIPs()
        local reason = "literal"
        if not ips then
            local target = ctx:GetOriginalTargetDomain()
            if target == "" then return deny("untrusted_destination") end
            local err
            ips, _, err = business_dns:Query(target, false, true, false)
            reason = "public_aaaa"
            if err then
                if not dns.IsNoData(err) then return deny("dns_aaaa") end
                -- Sequential requests cannot merge different generations.
                -- Agent returns no A if its current selection contains AAAA.
                ips, _, err = business_dns:Query(target, true, false, false)
                if err then return deny("dns_a_after_nodata") end
                reason = "confirmed_aaaa_nodata"
            end
        end
        if not ips or #ips == 0 or blocked:AnyMatch(ips) then return deny("unsafe_target") end
        local six = v6:FilterIPs(ips)
        local four = v4:FilterIPs(ips)
        -- A mixed result is not evidence of the selector contract.
        if #six > 0 and #four > 0 then return deny("mixed_selection") end
        ctx:SetTargetIP(ips, 1)
        if #six > 0 then return selected(route.ipv6, "ipv6", reason) end
        if #four > 0 then return selected(route.ipv4, "ipv4", reason) end
        return deny("unknown_family")
    end
    if native[inbound] and native[inbound][user] then return "direct", "glivela_native" end
    return deny("unknown_credential")
end
`)
	return script.String()
}

func validateRuntimeFiles(config []byte, files map[string][]byte) error {
	var envelope struct {
		Routing struct{ Script string }
		DNS     struct{ Script string }
	}
	if json.Unmarshal(config, &envelope) != nil {
		return errors.New("glivela: invalid runtime file manifest")
	}
	if envelope.DNS.Script != "" {
		return errors.New("glivela: global DNS scripts are not part of composite artifacts")
	}
	used := map[string]bool{}
	for _, script := range []string{envelope.Routing.Script} {
		if script == "" {
			continue
		}
		name := path.Base(script)
		contents, exists := files[name]
		if !exists || len(contents) == 0 || len(contents) > 1<<20 || script != path.Join(runtimeFileDirectory, name) || name != runtimeFileName("routing", contents) || used[name] {
			return errors.New("glivela: runtime script digest or scope changed")
		}
		used[name] = true
	}
	if len(files) != len(used) || len(files) > 1 {
		return errors.New("glivela: incomplete runtime file manifest")
	}
	return nil
}
