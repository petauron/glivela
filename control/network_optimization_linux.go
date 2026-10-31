//go:build linux

package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const networkSysctlFile = "/etc/sysctl.d/90-glivela-network.conf"
const networkBackupFile = "network-optimization.json"

type networkBackup struct {
	Original        NetworkSnapshot `json:"original"`
	Applied         NetworkSnapshot `json:"applied"`
	Content         string          `json:"content"`
	PreviousContent string          `json:"previousContent,omitempty"`
	BootID          string          `json:"bootId"`
	Pending         string          `json:"pending"`
	Result          *NetworkResult  `json:"result,omitempty"`
}

func networkTool(ctx context.Context, name string, args ...string) ([]byte, error) {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			return nativeEntryCommand(ctx, p, args...)
		}
	}
	return nil, fmt.Errorf("required tool unavailable: %s", name)
}
func networkRead(key string) (string, error) {
	raw, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	return strings.TrimSpace(string(raw)), err
}
func networkValues(key string) ([]int64, error) {
	v, err := networkRead(key)
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(v)
	out := make([]int64, len(parts))
	for i, p := range parts {
		n, e := strconv.ParseInt(p, 10, 64)
		if e != nil || n < 0 {
			return nil, errors.New("invalid kernel value")
		}
		out[i] = n
	}
	return out, nil
}
func networkWrite(key, value string) error {
	return os.WriteFile("/proc/sys/"+strings.ReplaceAll(key, ".", "/"), []byte(value), 0600)
}
func safeNetworkName(v string) bool {
	if v == "" || len(v) > 15 {
		return false
	}
	for _, c := range v {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}
func defaultNetworkInterface(ctx context.Context) (string, error) {
	iface := ""
	for _, family := range []string{"-4", "-6"} {
		raw, err := networkTool(ctx, "ip", "-j", family, "route", "show", "default")
		if err != nil {
			return "", err
		}
		var routes []struct {
			Dev       string          `json:"dev"`
			Multipath json.RawMessage `json:"multipath"`
		}
		if json.Unmarshal(raw, &routes) != nil {
			return "", errors.New("cannot inspect routes")
		}
		for _, r := range routes {
			if !safeNetworkName(r.Dev) || len(r.Multipath) > 0 || iface != "" && iface != r.Dev {
				return "", errors.New("multiple or complex exits: automatic tuning unavailable")
			}
			iface = r.Dev
		}
	}
	if iface == "" {
		return "", errors.New("default exit not found")
	}
	return iface, nil
}

// Only replace a single, default pfifo_fast/fq_codel root. MQ, ingress,
// shaping and nondefault fq_codel options are never overwritten.
func networkQdisc(ctx context.Context, iface string) (string, bool, error) {
	kind, simple, _, err := networkQueue(ctx, iface)
	return kind, simple, err
}
func networkQueue(ctx context.Context, iface string) (kind string, simple bool, fingerprint string, err error) {
	raw, err := networkTool(ctx, "tc", "-j", "qdisc", "show", "dev", iface)
	if err != nil {
		return "", false, "", err
	}
	var q []struct {
		Kind    string         `json:"kind"`
		Root    bool           `json:"root"`
		Options map[string]any `json:"options"`
	}
	if json.Unmarshal(raw, &q) != nil || len(q) != 1 || !q[0].Root {
		return "complex", false, "", nil
	}
	x := q[0]
	encoded, _ := json.Marshal(x)
	digest := sha256.Sum256(encoded)
	fingerprint = hex.EncodeToString(digest[:])
	if x.Kind == "fq" {
		return "fq", true, fingerprint, nil
	}
	if x.Kind == "pfifo_fast" {
		for k, v := range x.Options {
			if k == "bands" && v == float64(3) {
				continue
			}
			if k == "priomap" {
				raw, _ := json.Marshal(v)
				if string(raw) == "[1,2,2,2,1,2,0,0,1,1,1,1,1,1,1,1]" {
					continue
				}
			}
			return x.Kind, false, fingerprint, nil
		}
		return x.Kind, true, fingerprint, nil
	}
	if x.Kind != "fq_codel" {
		return x.Kind, false, fingerprint, nil
	}
	// tc versions differ in emitted defaults; unknown options fail closed.
	defaults := map[string]float64{"limit": 10240, "flows": 1024, "quantum": 1514, "target": 5000, "interval": 100000, "memory_limit": 33554432, "drop_batch": 64, "ce_threshold": 4294967295}
	for k, v := range x.Options {
		if k == "ecn" {
			if v != true {
				return x.Kind, false, fingerprint, nil
			}
			continue
		}
		// Some kernels round the default time values down by one microsecond.
		if k == "target" && (v == float64(4999) || v == float64(5000)) {
			continue
		}
		if k == "interval" && (v == float64(99999) || v == float64(100000)) {
			continue
		}
		want, ok := defaults[k]
		if !ok || v != want {
			return x.Kind, false, fingerprint, nil
		}
	}
	return x.Kind, true, fingerprint, nil
}
func networkAncestry(directory string) error {
	if !filepath.IsAbs(directory) {
		return errors.New("absolute network state directory required")
	}
	for p := directory; p != "/"; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe network state directory")
		}
		uid, e := entryFileUID(info)
		if e != nil || uid != 0 {
			return errors.New("network state must be root owned")
		}
	}
	return nil
}
func loadNetworkBackup(directory string) (*networkBackup, error) {
	if err := networkAncestry(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, networkBackupFile)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return nil, errors.New("unsafe network backup")
	}
	uid, ownerErr := entryFileUID(info)
	if ownerErr != nil || uid != 0 {
		return nil, errors.New("network backup must be root owned")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b networkBackup
	if json.Unmarshal(raw, &b) != nil {
		return nil, errors.New("invalid network backup")
	}
	return &b, nil
}
func saveNetworkBackup(directory string, b *networkBackup) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return networkAtomic(filepath.Join(directory, networkBackupFile), raw, 0600)
}
func networkAtomic(path string, raw []byte, mode os.FileMode) error {
	if err := networkAncestry(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("unsafe target file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".glivela-network-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func networkOwned(b *networkBackup) bool {
	info, err := os.Lstat(networkSysctlFile)
	if errors.Is(err, os.ErrNotExist) && b.Pending != "" && b.PreviousContent == "" {
		return true
	}
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	raw, err := os.ReadFile(networkSysctlFile)
	return err == nil && (string(raw) == b.Content || b.Pending != "" && string(raw) == b.PreviousContent)
}

// Containers share the host kernel. Detection must fail closed before any writes.
func networkIsContainer(ctx context.Context) (bool, error) {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container"} {
		if _, err := os.Stat(marker); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(check, "/usr/bin/systemd-detect-virt", "--container", "--quiet")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if check.Err() == nil && errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, errors.New("cannot determine whether environment is a container")
}

// Read actual values from the container namespace. No write or host mutation is allowed.
func inspectContainerNetwork(ctx context.Context, v NetworkSnapshot) NetworkSnapshot {
	v.Scope = "容器网络命名空间（只读）"
	v.Reason = "容器共享宿主内核，仅显示实际状态；不能修改 BBR/FQ"
	v.Kernel, _ = networkRead("kernel.osrelease")
	iface, err := defaultNetworkInterface(ctx)
	if err == nil {
		v.Interface = iface
		if mtu, e := os.ReadFile("/sys/class/net/" + iface + "/mtu"); e == nil {
			v.MTU, _ = strconv.Atoi(strings.TrimSpace(string(mtu)))
		}
		v.Qdisc, _, v.QdiscFingerprint, err = networkQueue(ctx, iface)
	}
	queueOK := err == nil && v.Qdisc != ""
	v.Congestion, err = networkRead("net.ipv4.tcp_congestion_control")
	congestionOK := err == nil && v.Congestion != ""
	if available, e := networkRead("net.ipv4.tcp_available_congestion_control"); e == nil {
		v.Available = strings.Fields(available)
	}
	v.DefaultQdisc, _ = networkRead("net.core.default_qdisc")
	for key, dst := range map[string]*[3]int64{"net.ipv4.tcp_rmem": &v.Receive, "net.ipv4.tcp_wmem": &v.Send} {
		if values, e := networkValues(key); e == nil && len(values) == 3 {
			copy(dst[:], values)
		}
	}
	for key, dst := range map[string]*int64{"net.core.rmem_max": &v.ReceiveMax, "net.core.wmem_max": &v.SendMax} {
		if values, e := networkValues(key); e == nil && len(values) == 1 {
			*dst = values[0]
		}
	}
	for key, dst := range map[string]*int{"net.ipv4.tcp_window_scaling": &v.Scaling, "net.ipv4.tcp_moderate_rcvbuf": &v.AutoReceive} {
		if values, e := networkValues(key); e == nil && len(values) == 1 {
			switch values[0] {
			case 0:
				*dst = 0
			case 1:
				*dst = 1
			}
		}
	}
	v.Observed = queueOK && congestionOK
	if !v.Observed {
		v.Reason += "；部分状态读取失败"
	}
	v.Fingerprint = networkDigest(v)
	return v
}

func inspectNetwork(ctx context.Context, directory string) NetworkSnapshot {
	v := NetworkSnapshot{CheckedAt: time.Now().UTC(), Scope: "host network namespace"}
	finish := func(reason string) NetworkSnapshot { v.Reason = reason; v.Fingerprint = networkDigest(v); return v }
	if os.Geteuid() != 0 {
		return finish("需要原生 root 节点端；不会提权")
	}
	container, detectionErr := networkIsContainer(ctx)
	if detectionErr != nil {
		return finish("无法确认容器环境，禁止修改")
	}
	if container {
		return inspectContainerNetwork(ctx, v)
	}
	self, err := os.Readlink("/proc/self/ns/net")
	init, e := os.Readlink("/proc/1/ns/net")
	if err != nil || e != nil || self != init {
		return finish("网络命名空间不同，禁止自动应用")
	}
	if v.Interface, err = defaultNetworkInterface(ctx); err != nil {
		return finish(err.Error())
	}
	mtu, err := os.ReadFile("/sys/class/net/" + v.Interface + "/mtu")
	if err != nil {
		return finish("无法读取出口 MTU")
	}
	v.MTU, _ = strconv.Atoi(strings.TrimSpace(string(mtu)))
	mem, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return finish("无法读取内存")
	}
	for _, line := range strings.Split(string(mem), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == "MemTotal:" {
			n, _ := strconv.ParseInt(parts[1], 10, 64)
			v.MemoryBytes = n * 1024
		}
	}
	v.Congestion, err = networkRead("net.ipv4.tcp_congestion_control")
	if err != nil {
		return finish("无法读取 TCP 算法")
	}
	avail, err := networkRead("net.ipv4.tcp_available_congestion_control")
	if err != nil {
		return finish("无法读取支持的算法")
	}
	v.Available = strings.Fields(avail)
	v.DefaultQdisc, err = networkRead("net.core.default_qdisc")
	if err != nil {
		return finish("无法读取默认队列")
	}
	for key, dst := range map[string]*[3]int64{"net.ipv4.tcp_rmem": &v.Receive, "net.ipv4.tcp_wmem": &v.Send} {
		values, err := networkValues(key)
		if err != nil || len(values) != 3 {
			return finish("无法读取 TCP 缓冲区")
		}
		copy(dst[:], values)
	}
	for key, dst := range map[string]*int64{"net.core.rmem_max": &v.ReceiveMax, "net.core.wmem_max": &v.SendMax} {
		values, err := networkValues(key)
		if err != nil || len(values) != 1 {
			return finish("无法读取 socket 上限")
		}
		*dst = values[0]
	}
	for key, dst := range map[string]*int{"net.ipv4.tcp_window_scaling": &v.Scaling, "net.ipv4.tcp_moderate_rcvbuf": &v.AutoReceive} {
		values, err := networkValues(key)
		if err != nil || len(values) != 1 || values[0] < 0 || values[0] > 1 {
			return finish("无法读取 TCP 自动调整状态")
		}
		*dst = 0
		if values[0] == 1 {
			*dst = 1
		}
	}
	var simple bool
	v.Qdisc, simple, v.QdiscFingerprint, err = networkQueue(ctx, v.Interface)
	if err != nil {
		return finish("无法读取实际出口队列；需要已有 iproute2")
	}
	v.Observed = true
	v.Kernel, _ = networkRead("kernel.osrelease")
	b, err := loadNetworkBackup(directory)
	if err != nil {
		return finish(err.Error())
	}
	v.CanRestore = b != nil && b.Content != "" && simple && v.Interface == b.Original.Interface
	if b != nil && b.Content != "" && !networkOwned(b) {
		v.CanRestore = false
		return finish("独立配置文件已被外部修改；保留现场，拒绝覆盖")
	}
	if b == nil || b.Content == "" {
		if _, err := os.Lstat(networkSysctlFile); !errors.Is(err, os.ErrNotExist) {
			return finish("存在未归属的 Glivela 网络配置；拒绝覆盖")
		}
	}
	if b != nil && b.Pending != "" {
		return finish("上次应用中断；请核对并恢复应用前配置")
	}
	if !simple {
		return finish("已有复杂/自定义队列；不覆盖整形")
	}
	if !slices.Contains(v.Available, "bbr") {
		return finish("当前内核未提供 BBR；不会安装内核或自动加载模块")
	}
	v.CanApply = true
	return finish("")
}
func networkText(v NetworkSnapshot) string {
	return fmt.Sprintf("# Managed by Glivela; restore from the network optimization panel.\nnet.ipv4.tcp_congestion_control = %s\nnet.core.default_qdisc = %s\nnet.ipv4.tcp_rmem = %d %d %d\nnet.ipv4.tcp_wmem = %d %d %d\nnet.core.rmem_max = %d\nnet.core.wmem_max = %d\n", v.Congestion, v.DefaultQdisc, v.Receive[0], v.Receive[1], v.Receive[2], v.Send[0], v.Send[1], v.Send[2], v.ReceiveMax, v.SendMax)
}
func applyNetworkValues(ctx context.Context, v NetworkSnapshot) error {
	if !safeNetworkName(v.Interface) || !slices.Contains([]string{"fq", "pfifo_fast", "fq_codel"}, v.Qdisc) {
		return errors.New("unsafe saved queue")
	}
	// The text is generated only from inspected kernel fields or fixed values.
	for _, line := range strings.Split(networkText(v), "\n") {
		key, value, ok := strings.Cut(line, " = ")
		if ok {
			if err := networkWrite(key, value); err != nil {
				return fmt.Errorf("内核拒绝参数 %s", key)
			}
		}
	}
	kind, _, err := networkQdisc(ctx, v.Interface)
	if err != nil {
		return err
	}
	if kind != v.Qdisc {
		if _, err = networkTool(ctx, "tc", "qdisc", "replace", "dev", v.Interface, "root", v.Qdisc); err != nil {
			return errors.New("出口队列应用失败")
		}
	}
	return nil
}
func sameNetworkValues(a, b NetworkSnapshot) bool {
	return a.Interface == b.Interface && a.Congestion == b.Congestion && a.DefaultQdisc == b.DefaultQdisc && a.Send == b.Send && a.Receive == b.Receive && a.SendMax == b.SendMax && a.ReceiveMax == b.ReceiveMax && a.Qdisc == b.Qdisc
}
func executeNetwork(ctx context.Context, directory string, c NetworkCommand) NetworkReport {
	current := inspectNetwork(ctx, directory)
	out := NetworkReport{Snapshot: current, Result: &NetworkResult{ID: c.ID, State: "failed"}}
	fail := func(message string) NetworkReport {
		out.Result.State = "failed"
		out.Result.Message = message
		out.Snapshot = inspectNetwork(ctx, directory)
		return out
	}
	b, err := loadNetworkBackup(directory)
	if err != nil {
		return fail(err.Error())
	}
	if b != nil && b.Result != nil && b.Result.ID == c.ID {
		out.Result = b.Result
		return out
	}
	if time.Now().After(c.ExpiresAt) || len(c.ID) > 128 {
		return fail("请求已过期，请重新检测")
	}
	if c.Action == "inspect" {
		out.Result.State = "succeeded"
		out.Result.Message = "已读取实际内核状态"
		return out
	}
	if c.Expected != current.Fingerprint {
		return fail("内核或出口状态已变化，请重新检测后确认")
	}
	if c.Action == "restore" {
		if b == nil || !current.CanRestore || !networkOwned(b) {
			return fail("没有可安全恢复的原配置")
		}
		if b.Pending == "" && (!sameNetworkValues(current, b.Applied) || current.QdiscFingerprint != b.Applied.QdiscFingerprint) {
			return fail("参数已被外部修改；拒绝覆盖")
		}
		b.Pending = c.ID
		if saveNetworkBackup(directory, b) != nil {
			return fail("无法记录恢复意图")
		}
		if err = applyNetworkValues(ctx, b.Original); err != nil {
			return fail("恢复未完成：" + err.Error())
		}
		actual := inspectNetwork(ctx, directory)
		if !sameNetworkValues(actual, b.Original) {
			return fail("恢复读回不一致，保留备份")
		}
		if !networkOwned(b) {
			return fail("持久配置已变化，拒绝移除")
		}
		if err = os.Remove(networkSysctlFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail("无法移除自有持久配置，保留备份")
		}
		b.Content = ""
		b.PreviousContent = ""
		b.Pending = ""
		out.Result.State = "succeeded"
		out.Result.Message = "已恢复应用前配置"
		b.Result = out.Result
		if saveNetworkBackup(directory, b) != nil {
			return fail("恢复完成但记录保存失败，请核对")
		}
		out.Snapshot = inspectNetwork(ctx, directory)
		return out
	}
	if c.Action != "apply" || !current.CanApply {
		return fail("此环境不支持自动应用")
	}
	if c.BufferBytes < 0 || c.BufferBytes > min(current.MemoryBytes/32, 256<<20) || c.BufferBytes != 0 && c.BufferBytes < 4<<20 {
		return fail("缓冲建议超过内存预算")
	}
	target := current
	target.Congestion = "bbr"
	target.DefaultQdisc = "fq"
	target.Qdisc = "fq"
	if c.BufferBytes > 0 {
		target.Send[2] = max(target.Send[2], c.BufferBytes)
		target.Receive[2] = max(target.Receive[2], c.BufferBytes)
		target.SendMax = max(target.SendMax, c.BufferBytes)
		target.ReceiveMax = max(target.ReceiveMax, c.BufferBytes)
	}
	if b == nil || b.Content == "" {
		b = &networkBackup{Original: current}
	}
	if b.Content != "" && (!sameNetworkValues(current, b.Applied) || current.QdiscFingerprint != b.Applied.QdiscFingerprint) {
		return fail("先前应用后参数被外部修改；拒绝覆盖")
	}
	b.Pending = c.ID
	b.Applied = target
	b.PreviousContent = b.Content
	b.Content = networkText(target)
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	b.BootID = strings.TrimSpace(string(boot))
	if saveNetworkBackup(directory, b) != nil {
		return fail("备份失败，未应用")
	}
	if err = networkAtomic(networkSysctlFile, []byte(b.Content), 0644); err == nil {
		err = applyNetworkValues(ctx, target)
	}
	actual := inspectNetwork(ctx, directory)
	if err != nil || !sameNetworkValues(actual, target) {
		// No automatic retry of partially applied mutations. A fresh explicit
		// restore remains possible; preserve the durable original snapshot.
		return fail("应用未完整确认；保留原配置备份，请核对并恢复")
	}
	b.Applied = actual
	b.Pending = ""
	out.Result.State = "succeeded"
	out.Result.Message = "BBR/FQ 与所选缓冲上限已读回确认；既有连接可能继续使用旧算法"
	b.Result = out.Result
	if saveNetworkBackup(directory, b) != nil {
		return fail("应用已执行，但结果保存失败；请核对")
	}
	out.Snapshot = inspectNetwork(ctx, directory)
	return out
}

// sysctl.d persists parameters. Re-establish only our simple FQ on a new
// boot; never reset a queue on process restarts or replace custom shaping.
func resumeNetwork(ctx context.Context, directory string) {
	b, err := loadNetworkBackup(directory)
	if err != nil || b == nil || b.Content == "" || b.Pending != "" || !networkOwned(b) {
		return
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) == b.BootID {
		return
	}
	v := inspectNetwork(ctx, directory)
	if !v.CanApply || v.Interface != b.Applied.Interface {
		return
	}
	if b.Original.Qdisc == "fq" && v.Qdisc != "fq" {
		return
	}
	before := v
	before.Qdisc = b.Applied.Qdisc
	if !sameNetworkValues(before, b.Applied) {
		return
	}
	if err = applyNetworkValues(ctx, b.Applied); err != nil {
		return
	}
	v = inspectNetwork(ctx, directory)
	if !sameNetworkValues(v, b.Applied) {
		return
	}
	b.Applied = v
	b.BootID = strings.TrimSpace(string(boot))
	_ = saveNetworkBackup(directory, b)
}
