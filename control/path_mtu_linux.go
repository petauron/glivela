//go:build linux

package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const pathMTUFile = "path-mtu.json"
const pathMTUProtocol = "242"

type pathKernelRoute struct {
	Destination string `json:"dst"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"dev"`
	Source      string `json:"prefsrc,omitempty"`
	Protocol    string `json:"protocol"`
	Scope       string `json:"scope,omitempty"`
	Metric      int    `json:"metric,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
	Onlink      bool   `json:"onlink,omitempty"`
}
type pathMTUPending struct {
	ID   string           `json:"id"`
	Next *pathKernelRoute `json:"next,omitempty"`
}
type pathMTURecord struct {
	Address string           `json:"address"`
	Base    pathKernelRoute  `json:"base"`
	Applied *pathKernelRoute `json:"applied,omitempty"`
	BootID  string           `json:"bootId"`
	Pending *pathMTUPending  `json:"pending,omitempty"`
	Result  *NetworkResult   `json:"result,omitempty"`
}
type pathMTUState struct {
	Routes map[string]pathMTURecord `json:"routes"`
}

func pathHost(address string) string {
	a, _ := netip.ParseAddr(address)
	return netip.PrefixFrom(a, a.BitLen()).String()
}
func pathFamily(address string) string {
	a, _ := netip.ParseAddr(address)
	if a.Is6() {
		return "-6"
	}
	return "-4"
}
func pathBoot() string {
	v, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(v))
}
func pathLoad(directory string) (pathMTUState, error) {
	b := pathMTUState{Routes: map[string]pathMTURecord{}}
	if err := networkAncestry(directory); err != nil {
		return b, err
	}
	p := filepath.Join(directory, pathMTUFile)
	info, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return b, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return b, errors.New("路径 MTU 状态文件不可信")
	}
	uid, e := entryFileUID(info)
	if e != nil || uid != 0 {
		return b, errors.New("路径 MTU 状态必须由 root 持有")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return b, err
	}
	if json.Unmarshal(raw, &b) != nil || b.Routes == nil || len(b.Routes) > 32 {
		return b, errors.New("路径 MTU 状态损坏")
	}
	for address, v := range b.Routes {
		if !pathMTUAddress(address) || v.Address != address || v.Applied != nil && (v.Applied.Destination != pathHost(address) || v.Applied.Protocol != pathMTUProtocol || !safeNetworkName(v.Applied.Interface)) || v.Pending != nil && v.Pending.Next != nil && (v.Pending.Next.Destination != pathHost(address) || v.Pending.Next.Protocol != pathMTUProtocol || !safeNetworkName(v.Pending.Next.Interface)) {
			return b, errors.New("路径 MTU 归属记录无效")
		}
	}
	return b, nil
}
func pathSave(directory string, b pathMTUState) error {
	if err := networkAncestry(directory); err != nil {
		return err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if len(raw) > 65536 {
		return errors.New("路径 MTU 状态超过上限")
	}
	return networkAtomic(filepath.Join(directory, pathMTUFile), raw, 0600)
}

func pathParseRoute(raw map[string]any) (pathKernelRoute, error) {
	r := pathKernelRoute{}
	for k := range raw {
		switch k {
		case "dst", "gateway", "dev", "prefsrc", "protocol", "scope", "metric", "flags", "pref", "expires", "metrics", "type":
		default:
			return r, errors.New("存在复杂路由属性，拒绝自动修改")
		}
	}
	text := func(k string) string { v, _ := raw[k].(string); return v }
	if text("type") != "" && text("type") != "unicast" {
		return r, errors.New("目标不是普通单路径路由")
	}
	r.Destination = text("dst")
	r.Gateway = text("gateway")
	r.Interface = text("dev")
	r.Source = text("prefsrc")
	r.Scope = text("scope")
	if r.Scope == "global" {
		r.Scope = ""
	}
	if v := raw["protocol"]; v != nil {
		r.Protocol = fmt.Sprint(v)
	}
	if v, ok := raw["metric"].(float64); ok {
		r.Metric = int(v)
	}
	if !safeNetworkName(r.Interface) {
		return r, errors.New("目标出口网卡未确认")
	}
	if r.Gateway != "" {
		if a, e := netip.ParseAddr(r.Gateway); e != nil || !a.IsValid() {
			return r, errors.New("下一跳地址无效")
		}
	}
	if r.Source != "" {
		if a, e := netip.ParseAddr(r.Source); e != nil || !a.IsValid() {
			return r, errors.New("源地址无效")
		}
	}
	if flags, ok := raw["flags"].([]any); ok {
		for _, f := range flags {
			if f != "onlink" {
				return r, errors.New("路由标记不支持")
			}
			r.Onlink = true
		}
	}
	mtu, err := pathRouteMTU(raw["metrics"])
	if err != nil {
		return r, err
	}
	r.MTU = mtu
	return r, nil
}

func pathRouteMTU(raw any) (int, error) {
	if raw == nil {
		return 0, nil
	}
	metrics, ok := raw.([]any)
	if !ok || len(metrics) != 1 {
		return 0, errors.New("目标路由参数无法核验")
	}
	values, ok := metrics[0].(map[string]any)
	if !ok || len(values) != 1 {
		return 0, errors.New("目标路由还有其他自定义参数")
	}
	n, ok := values["mtu"].(float64)
	if !ok || n != float64(int(n)) || n < 576 || n > 65535 {
		return 0, errors.New("路由 MTU 无效")
	}
	return int(n), nil
}

func pathRoutes(ctx context.Context, address string) ([]pathKernelRoute, error) {
	raw, err := networkTool(ctx, "ip", "-j", pathFamily(address), "route", "show", "table", "main")
	if err != nil {
		return nil, errors.New("无法读取主路由表")
	}
	var rows []map[string]any
	if len(raw) > 1<<20 || json.Unmarshal(raw, &rows) != nil || len(rows) > 4096 {
		return nil, errors.New("路由表超出可安全处理范围")
	}
	a, _ := netip.ParseAddr(address)
	var out []pathKernelRoute
	for _, row := range rows {
		dst, _ := row["dst"].(string)
		prefix := dst
		if dst == "default" {
			prefix = "0.0.0.0/0"
			if a.Is6() {
				prefix = "::/0"
			}
		}
		if !strings.Contains(prefix, "/") {
			prefix = pathHost(prefix)
		}
		p, e := netip.ParsePrefix(prefix)
		if e != nil || !p.Contains(a) {
			continue
		}
		r, e := pathParseRoute(row)
		if e != nil {
			return nil, e
		}
		r.Destination = p.String()
		out = append(out, r)
	}
	return out, nil
}

func pathInspect(ctx context.Context, directory, address string) (PathMTUObservation, pathKernelRoute, *pathKernelRoute, error) {
	v := PathMTUObservation{Address: address, CheckedAt: time.Now().UTC()}
	var base pathKernelRoute
	fail := func(e error) (PathMTUObservation, pathKernelRoute, *pathKernelRoute, error) {
		v.Reason = e.Error()
		return v, base, nil, e
	}
	if !pathMTUAddress(address) {
		return fail(errors.New("仅支持已登记的公网目标"))
	}
	state, err := pathLoad(directory)
	if err != nil {
		return fail(err)
	}
	record := state.Routes[address]
	if record.Applied != nil {
		v.Configured = record.Applied.MTU
	}
	routes, err := pathRoutes(ctx, address)
	if err != nil {
		return fail(err)
	}
	var exact *pathKernelRoute
	var parents []pathKernelRoute
	for _, r := range routes {
		r := r
		if r.Destination == pathHost(address) {
			if exact != nil {
				return fail(errors.New("目标有多条主机路由"))
			}
			exact = &r
		} else {
			parents = append(parents, r)
		}
	}
	owned := exact != nil && (reflect.DeepEqual(exact, record.Applied) || record.Pending != nil && reflect.DeepEqual(exact, record.Pending.Next))
	if exact != nil && !owned {
		return fail(errors.New("目标已有非 Glivela 主机路由，保持原样"))
	}
	if len(parents) == 0 {
		return fail(errors.New("缺少目标的基础路由"))
	}
	sort.Slice(parents, func(i, j int) bool {
		pi, _ := netip.ParsePrefix(parents[i].Destination)
		pj, _ := netip.ParsePrefix(parents[j].Destination)
		if pi.Bits() != pj.Bits() {
			return pi.Bits() > pj.Bits()
		}
		return parents[i].Metric < parents[j].Metric
	})
	base = parents[0]
	if len(parents) > 1 && base.Destination == parents[1].Destination && base.Metric == parents[1].Metric && !reflect.DeepEqual(base, parents[1]) {
		return fail(errors.New("目标存在等价或复杂出口"))
	}
	raw, err := networkTool(ctx, "ip", "-j", pathFamily(address), "route", "get", address)
	var actual []map[string]any
	if err != nil || json.Unmarshal(raw, &actual) != nil || len(actual) != 1 {
		return fail(errors.New("实际目标路由不可用"))
	}
	get := actual[0]
	if table, ok := get["table"]; ok && fmt.Sprint(table) != "main" && fmt.Sprint(table) != "254" {
		return fail(errors.New("目标使用策略路由表，保持原样"))
	}
	chosen := base
	if owned {
		chosen = *exact
	}
	if get["dev"] != chosen.Interface || fmt.Sprint(get["gateway"]) != fmt.Sprint(func() any {
		if chosen.Gateway == "" {
			return nil
		}
		return chosen.Gateway
	}()) {
		return fail(errors.New("实际下一跳与受管路径不一致"))
	}
	if base.Source == "" {
		base.Source, _ = get["prefsrc"].(string)
	}
	if _, e := netip.ParseAddr(base.Source); e != nil {
		return fail(errors.New("无法确认目标路径源地址"))
	}
	iface, e := net.InterfaceByName(base.Interface)
	if e != nil {
		return fail(e)
	}
	assigned, e := iface.Addrs()
	if e != nil {
		return fail(e)
	}
	hasSource := false
	for _, item := range assigned {
		if prefix, e := netip.ParsePrefix(item.String()); e == nil && prefix.Addr().String() == base.Source {
			hasSource = true
		}
	}
	if !hasSource {
		return fail(errors.New("原路径源地址已不在出口网卡上"))
	}
	mtuRaw, err := os.ReadFile("/sys/class/net/" + base.Interface + "/mtu")
	if err != nil {
		return fail(err)
	}
	v.Interface = base.Interface
	v.InterfaceMTU, err = strconv.Atoi(strings.TrimSpace(string(mtuRaw)))
	if err != nil {
		return fail(err)
	}
	v.Actual = v.InterfaceMTU
	if base.MTU > 0 {
		v.Actual = min(v.Actual, base.MTU)
	}
	if exact != nil {
		v.Configured = exact.MTU
		v.Actual = min(v.Actual, exact.MTU)
	}
	if mtu, e := pathRouteMTU(get["metrics"]); e != nil {
		return fail(e)
	} else if mtu > 0 {
		v.Actual = min(v.Actual, mtu)
	}
	data, _ := json.Marshal(struct {
		Base         pathKernelRoute
		Exact        *pathKernelRoute
		Record       pathMTURecord
		InterfaceMTU int
	}{base, exact, record, v.InterfaceMTU})
	digest := sha256.Sum256(data)
	v.Fingerprint = hex.EncodeToString(digest[:])
	v.CanRestore = owned || exact == nil && (record.Pending != nil || record.Applied != nil)
	if os.Geteuid() != 0 {
		v.Reason = "修改路径 MTU 需要原生节点 root 权限"
		return v, base, exact, nil
	}
	self, e1 := os.Stat("/proc/self/ns/net")
	init, e2 := os.Stat("/proc/1/ns/net")
	if e1 != nil || e2 != nil || !os.SameFile(self, init) {
		v.Reason = "节点与 PID 1 网络命名空间不同"
		v.CanRestore = false
		return v, base, exact, nil
	}
	if record.Pending != nil || owned && !reflect.DeepEqual(base, record.Base) {
		v.Reason = "出口已变化或上次操作未确认，请先恢复自动"
		return v, base, exact, nil
	}
	if record.Applied != nil && !owned {
		v.Reason = "自有路由已被外部移除，请核对"
		return v, base, exact, nil
	}
	v.CanChange = true
	return v, base, exact, nil
}

func pathRouteArgs(action, address string, r pathKernelRoute) []string {
	args := []string{pathFamily(address), "route", action, pathHost(address), "proto", pathMTUProtocol, "dev", r.Interface}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	if r.Source != "" && action != "del" {
		args = append(args, "src", r.Source)
	}
	if r.Metric > 0 {
		args = append(args, "metric", strconv.Itoa(r.Metric))
	}
	if action != "del" {
		if r.Scope != "" {
			args = append(args, "scope", r.Scope)
		}
		if r.Onlink {
			args = append(args, "onlink")
		}
		args = append(args, "mtu", strconv.Itoa(r.MTU))
	}
	return args
}
func pathWrite(ctx context.Context, action, address string, r pathKernelRoute) error {
	_, err := networkTool(ctx, "ip", pathRouteArgs(action, address, r)...)
	return err
}

func executePathMTU(ctx context.Context, directory string, c NetworkCommand) NetworkReport {
	ctx, cancel := context.WithDeadline(ctx, c.ExpiresAt)
	defer cancel()
	out := NetworkReport{Snapshot: inspectNetwork(ctx, directory), PathMTUSupported: true, Result: &NetworkResult{ID: c.ID, State: "failed"}}
	if c.PathMTU == nil {
		return out
	}
	address := c.PathMTU.Address
	finish := func(message string) NetworkReport {
		v, _, _, _ := pathInspect(ctx, directory, address)
		out.Paths = []PathMTUObservation{v}
		out.Result.Message = message
		return out
	}
	if len(c.ID) == 0 || len(c.ID) > 128 || time.Now().After(c.ExpiresAt) {
		return finish("请求已过期，请重新检测")
	}
	v, base, exact, err := pathInspect(ctx, directory, address)
	if err != nil {
		return finish(err.Error())
	}
	state, err := pathLoad(directory)
	if err != nil {
		return finish(err.Error())
	}
	record := state.Routes[address]
	if record.Result != nil && record.Result.ID == c.ID && record.Pending == nil {
		out.Result = record.Result
		return finish(out.Result.Message)
	}
	if c.Action == "path-inspect" {
		out.Result.State = "succeeded"
		return finish("已读取实际目标路径")
	}
	if c.Expected != v.Fingerprint {
		return finish("路径或设置已变化，请重新检测")
	}
	if c.Action != "path-auto" && c.Action != "path-set" {
		return finish("未知路径操作")
	}
	if c.Action == "path-auto" && !v.CanChange && !v.CanRestore || c.Action == "path-set" && !v.CanChange {
		return finish(v.Reason)
	}
	if c.Action == "path-set" && (c.PathMTU.MTU < pathMTUMin(address) || c.PathMTU.MTU > v.InterfaceMTU) {
		return finish("MTU 超出地址族或网卡允许范围")
	}
	if len(state.Routes) >= 32 && record.Address == "" {
		return finish("路径设置数量已达上限")
	}
	before := record
	var next *pathKernelRoute
	if c.Action == "path-set" {
		r := base
		r.Destination = pathHost(address)
		r.Protocol = pathMTUProtocol
		r.MTU = c.PathMTU.MTU
		if pathFamily(address) == "-6" && r.Metric == 0 {
			r.Metric = 1024
		}
		next = &r
	}
	record.Address = address
	record.Base = base
	record.BootID = pathBoot()
	record.Pending = &pathMTUPending{ID: c.ID, Next: next}
	state.Routes[address] = record
	if pathSave(directory, state) != nil {
		return finish("无法保存恢复意图，尚未修改路由")
	}
	if next != nil {
		// Delete only the known owned route, then add exclusively. A concurrent
		// foreign route must cause refusal, never be overwritten by replace.
		if exact != nil && !reflect.DeepEqual(exact, next) {
			err = pathWrite(ctx, "del", address, *exact)
		}
		if err == nil && !reflect.DeepEqual(exact, next) {
			err = pathWrite(ctx, "add", address, *next)
		}
	} else if exact != nil {
		err = pathWrite(ctx, "del", address, *exact)
	}
	if err == nil {
		_, _, current, e := pathInspect(ctx, directory, address)
		if e != nil || !reflect.DeepEqual(current, next) {
			err = errors.New("路由读回与请求不一致")
		}
	}
	if err != nil {
		// Restore only a route matching this durable intent. Never overwrite a foreign route.
		_, _, current, e := pathInspect(ctx, directory, address)
		if e == nil && reflect.DeepEqual(current, exact) {
			state.Routes[address] = before
			if before.Address == "" {
				delete(state.Routes, address)
			}
			_ = pathSave(directory, state)
		} else if e == nil && (reflect.DeepEqual(current, next) || current == nil) {
			if current != nil {
				e = pathWrite(ctx, "del", address, *current)
			}
			if e == nil && exact != nil {
				e = pathWrite(ctx, "add", address, *exact)
			}
			if e == nil {
				_, _, actual, readErr := pathInspect(ctx, directory, address)
				if readErr != nil || !reflect.DeepEqual(actual, exact) {
					e = errors.New("原路径恢复未确认")
				}
			}
			if e == nil {
				state.Routes[address] = before
				if before.Address == "" {
					delete(state.Routes, address)
				}
				_ = pathSave(directory, state)
			}
		}
		return finish("应用未确认；已尽可能保留原路径，请重新检测：" + err.Error())
	}
	record.Applied = next
	record.Pending = nil
	record.Result = &NetworkResult{ID: c.ID, State: "succeeded", Message: "已应用路径 MTU 并读回确认"}
	if next == nil {
		record.Result.Message = "已恢复系统自动路径 MTU"
	}
	state.Routes[address] = record
	if pathSave(directory, state) != nil {
		return finish("路由已执行但记录未确认，请重新检测后恢复自动")
	}
	out.Result = record.Result
	return finish(record.Result.Message)
}

func observePathMTUs(ctx context.Context, directory string) []PathMTUObservation {
	state, err := pathLoad(directory)
	if err != nil {
		return nil
	}
	var out []PathMTUObservation
	for address := range state.Routes {
		if ctx.Err() != nil {
			break
		}
		v, _, _, _ := pathInspect(ctx, directory, address)
		out = append(out, v)
	}
	return out
}

func resumePathMTUs(ctx context.Context, directory string, desired Desired) {
	state, err := pathLoad(directory)
	if err != nil {
		return
	}
	boot := pathBoot()
	if boot == "" {
		return
	}
	for address, record := range state.Routes {
		if record.Applied == nil || record.Pending != nil || record.BootID == boot || !pathMTUAllowed(desired, address) {
			continue
		}
		v, base, exact, e := pathInspect(ctx, directory, address)
		if e != nil || exact != nil || !reflect.DeepEqual(base, record.Base) || record.Applied.MTU > v.InterfaceMTU {
			continue
		}
		if pathWrite(ctx, "add", address, *record.Applied) != nil {
			continue
		}
		_, _, actual, e := pathInspect(ctx, directory, address)
		if e == nil && reflect.DeepEqual(actual, record.Applied) {
			record.BootID = boot
			state.Routes[address] = record
			_ = pathSave(directory, state)
		}
	}
}
