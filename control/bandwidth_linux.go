//go:build linux

package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type speedProcess struct {
	cmd  *exec.Cmd
	done chan error
}
type speedGuard struct {
	Family, Table, Chain, Set string
	Handle                    int
}

var speedPorts = []struct {
	port    int
	counter string
}{
	{speedPort, "c_du"}, {speedDownPort, "c_dd"},
	{speedSSPort, "c_su"}, {speedSSDownPort, "c_sd"},
}

type speedSession struct {
	mu                                        sync.Mutex
	directory, binary, digest, dir, table, id string
	hostGuardTable                            string
	iperfBinary, iperfDigest                  string
	processes                                 []*speedProcess
	guards                                    []speedGuard
	cancel                                    context.CancelFunc
	cleanupTimer                              *time.Timer
	progress                                  func(string, SpeedPoint)
}

func newSpeedSession(directory, binary, digest, iperfBinary, iperfDigest string) *speedSession {
	return &speedSession{hostGuardTable: "host_guard", directory: directory, binary: binary, digest: digest, iperfBinary: iperfBinary, iperfDigest: iperfDigest}
}
func (s *speedSession) setProgress(fn func(string, SpeedPoint)) { s.progress = fn }
func speedExec(ctx context.Context, binary string, args ...string) ([]byte, error) {
	var out limitedSpeedOutput
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	return out.Bytes(), err
}

// Stop unbounded tool output before it can exhaust a small host.
type limitedSpeedOutput struct{ bytes.Buffer }

func (b *limitedSpeedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, errors.New("output_limit")
	}
	return b.Buffer.Write(p)
}
func speedNFT(ctx context.Context, text string) error {
	cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
	cmd.Stdin = strings.NewReader(text)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return errors.New("temporary_firewall_unavailable")
	}
	return nil
}
func (s *speedSession) start(ctx context.Context, binary string, args ...string) (*speedProcess, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	if cmd.Start() != nil {
		return nil, errors.New("temporary_process_failed")
	}
	p := &speedProcess{cmd: cmd, done: make(chan error, 1)}
	s.processes = append(s.processes, p)
	go func() { p.done <- cmd.Wait(); close(p.done) }()
	return p, nil
}

// A private intent record lets the same installed node remove only its own
// expired diagnostics after a crash. No production resource is recorded here.
type speedResources struct {
	ID     string       `json:"id"`
	Table  string       `json:"table"`
	Guards []speedGuard `json:"guards"`
}

func (s *speedSession) remember() error {
	raw, err := json.Marshal(speedResources{s.id, s.table, s.guards})
	if err != nil {
		return err
	}
	temp := filepath.Join(s.dir, "resources.tmp")
	if os.WriteFile(temp, raw, 0600) != nil {
		return errors.New("private_intent_failed")
	}
	return os.Rename(temp, filepath.Join(s.dir, "resources.json"))
}
func (s *speedSession) recover() error {
	if err := s.loadHostGuard(); err != nil {
		return err
	}
	dirs, err := filepath.Glob(filepath.Join(s.directory, "speed-*"))
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("unsafe_speed_resources")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return errors.New("unsafe_speed_resources")
		}
		path := filepath.Join(dir, "resources.json")
		meta, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) > 1 || len(entries) == 1 && entries[0].Name() != "resources.tmp" {
				return errors.New("speed_recovery_unconfirmed")
			}
			if len(entries) == 1 {
				if os.Remove(filepath.Join(dir, "resources.tmp")) != nil {
					return errors.New("speed_recovery_unconfirmed")
				}
			}
			if os.Remove(dir) != nil {
				return errors.New("speed_recovery_unconfirmed")
			}
			continue
		}
		if err != nil || !meta.Mode().IsRegular() || meta.Mode().Perm() != 0600 || meta.Size() > 8192 {
			return errors.New("unsafe_speed_resources")
		}
		raw, err := os.ReadFile(path)
		var record speedResources
		if err != nil || json.Unmarshal(raw, &record) != nil || !speedID(record.ID) {
			return errors.New("unsafe_speed_resources")
		}
		suffix := strings.ReplaceAll(record.ID, "-", "")
		if record.Table != "" && record.Table != "glivela_speed_"+suffix {
			return errors.New("unsafe_speed_resources")
		}
		for _, g := range record.Guards {
			if g.Family != "inet" || g.Table != s.hostGuardTable || g.Chain != "input" || g.Set != "speed_"+suffix {
				return errors.New("unsafe_speed_resources")
			}
		}
		s.id, s.dir, s.table, s.guards = record.ID, dir, record.Table, record.Guards
		if s.close() != nil {
			return errors.New("speed_recovery_unconfirmed")
		}
	}
	return nil
}
func (s *speedSession) close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.closeLocked() }
func (s *speedSession) closeLocked() error {
	if s.cleanupTimer != nil {
		s.cleanupTimer.Stop()
		s.cleanupTimer = nil
	}
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	for _, p := range s.processes {
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			return errors.New("process_cleanup_unconfirmed")
		}
	}
	s.processes = nil
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	for _, g := range s.guards {
		raw, err := speedExec(ctx, "/usr/sbin/nft", "-j", "list", "chain", g.Family, g.Table, g.Chain)
		if err != nil {
			return errors.New("firewall_cleanup_unconfirmed")
		}
		var listing struct {
			NFTables []struct {
				Rule *struct {
					Handle  int
					Comment string
				} `json:"rule"`
			} `json:"nftables"`
		}
		if json.Unmarshal(raw, &listing) != nil {
			return errors.New("firewall_cleanup_unconfirmed")
		}
		for _, v := range listing.NFTables {
			if v.Rule != nil && v.Rule.Comment == "glivela-speed:"+s.id {
				if _, err = speedExec(ctx, "/usr/sbin/nft", "delete", "rule", g.Family, g.Table, g.Chain, "handle", strconv.Itoa(v.Rule.Handle)); err != nil {
					return errors.New("firewall_cleanup_unconfirmed")
				}
			}
		}
		if _, present := speedExec(ctx, "/usr/sbin/nft", "list", "set", g.Family, g.Table, g.Set); present == nil {
			if _, err = speedExec(ctx, "/usr/sbin/nft", "delete", "set", g.Family, g.Table, g.Set); err != nil {
				return errors.New("firewall_cleanup_unconfirmed")
			}
		}
	}
	s.guards = nil
	if s.table != "" {
		// A full successful ruleset read distinguishes already-absent objects from
		// lost privileges/tool failure during idempotent recovery.
		raw, err := speedExec(ctx, "/usr/sbin/nft", "-j", "list", "ruleset")
		if err != nil {
			return errors.New("firewall_cleanup_unconfirmed")
		}
		var listing struct {
			NFTables []struct {
				Table *struct{ Family, Name, Comment string } `json:"table"`
			} `json:"nftables"`
		}
		if json.Unmarshal(raw, &listing) != nil {
			return errors.New("firewall_cleanup_unconfirmed")
		}
		present := false
		owned := false
		for _, v := range listing.NFTables {
			if v.Table != nil && v.Table.Family == "inet" && v.Table.Name == s.table {
				present = true
				owned = v.Table.Comment == "glivela-speed:"+s.id
			}
		}
		if present && !owned {
			return errors.New("firewall_ownership_changed")
		}
		if present {
			if _, err = speedExec(ctx, "/usr/sbin/nft", "delete", "table", "inet", s.table); err != nil {
				return errors.New("firewall_cleanup_unconfirmed")
			}
		}
		s.table = ""
	}

	if s.dir != "" {
		if filepath.Dir(s.dir) != s.directory || !strings.HasPrefix(filepath.Base(s.dir), "speed-") {
			return errors.New("cleanup_ownership_changed")
		}
		if os.RemoveAll(s.dir) != nil {
			return errors.New("file_cleanup_unconfirmed")
		}
		s.dir = ""
	}
	s.id = ""
	return nil
}
func (s *speedSession) prerequisites(ctx context.Context, p SpeedAssignment) error {
	if os.Geteuid() != 0 {
		return errors.New("native_root_permission_required")
	}
	info, err := os.Lstat(s.iperfBinary)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("iperf3_not_installed")
	}
	if err != nil || !info.Mode().IsRegular() || verifyExecutableFile(s.iperfBinary, s.iperfDigest) != nil {
		return errors.New("iperf3_unavailable")
	}
	out, err := speedExec(ctx, s.iperfBinary, "--version")
	match := regexp.MustCompile(`iperf 3\.([0-9]+)`).FindSubmatch(out)
	if err != nil || len(match) != 2 {
		return errors.New("iperf3_version_invalid")
	}
	minor, _ := strconv.Atoi(string(match[1]))
	if minor != 22 {
		return errors.New("iperf3_version_invalid")
	}
	help, err := speedExec(ctx, s.iperfBinary, "--help")
	if err != nil || !bytes.Contains(help, []byte("--rsa-private-key-path")) {
		return errors.New("iperf3_authentication_required")
	}
	mem, err := os.ReadFile("/proc/meminfo")
	var available int64
	for _, line := range strings.Split(string(mem), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			_, _ = fmt.Sscanf(line, "MemAvailable: %d kB", &available)
		}
	}
	var fs syscall.Statfs_t
	if err != nil || available < 128*1024 || syscall.Statfs(s.directory, &fs) != nil || fs.Bavail*uint64(fs.Bsize) < 32<<20 {
		return errors.New("insufficient_memory_or_disk")
	}
	for _, mode := range p.Modes {
		if mode == "ss2022" && verifyExecutableFile(s.binary, s.digest) != nil {
			return errors.New("signed_xray_unavailable")
		}
	}
	return nil
}
func (s *speedSession) firewall(ctx context.Context, p SpeedAssignment) error {
	suffix := strings.ReplaceAll(p.ID, "-", "")
	if len(suffix) > 32 {
		suffix = suffix[:32]
	}
	s.table = "glivela_speed_" + suffix
	if _, err := speedExec(ctx, "/usr/sbin/nft", "list", "table", "inet", s.table); err == nil {
		s.table = ""
		return errors.New("test_resource_busy")
	}
	if s.remember() != nil {
		return errors.New("private_intent_failed")
	}
	peer := p.Address
	incoming, outgoing := "sport", "dport"
	if p.Role == "receiver" {
		peer = p.Source
		incoming, outgoing = "dport", "sport"
	}
	// Count both IP packet directions for each subtest, including TCP ACKs.
	family, addrType, otherFamily := "ip", "ipv4_addr", "ipv6"
	if netip.MustParseAddr(p.Address).Is6() {
		family, addrType, otherFamily = "ip6", "ipv6_addr", "ipv4"
	}
	var rules strings.Builder
	fmt.Fprintf(&rules, "table inet %s {\n comment \"glivela-speed:%s\"\n set peer { type %s; flags timeout; timeout 240s; elements = { %s timeout 240s }; }\n", s.table, p.ID, addrType, peer)
	for _, spec := range speedPorts {
		fmt.Fprintf(&rules, "counter %s { }\n", spec.counter)
	}
	rules.WriteString("chain input { type filter hook input priority -250; policy accept;\n")
	for _, spec := range speedPorts {
		fmt.Fprintf(&rules, "%s saddr @peer tcp %s %d counter name \"%s\"\n", family, incoming, spec.port, spec.counter)
	}
	if p.Role == "receiver" {
		fmt.Fprintf(&rules, "iifname != \"lo\" meta nfproto %s tcp dport { %d, %d, %d, %d } drop\n", otherFamily, speedPort, speedSSPort, speedDownPort, speedSSDownPort)
		fmt.Fprintf(&rules, "iifname != \"lo\" %s saddr != @peer tcp dport { %d, %d, %d, %d } drop\n", family, speedPort, speedSSPort, speedDownPort, speedSSDownPort)
	}
	rules.WriteString("}\nchain output { type filter hook output priority -250; policy accept;\n")
	for _, spec := range speedPorts {
		fmt.Fprintf(&rules, "%s daddr @peer tcp %s %d counter name \"%s\"\n", family, outgoing, spec.port, spec.counter)
	}
	rules.WriteString("}\n}\n")
	if err := speedNFT(ctx, rules.String()); err != nil {
		s.table = ""
		return err
	}
	if p.Role != "receiver" {
		return nil
	}
	raw, err := speedExec(ctx, "/usr/sbin/nft", "-j", "list", "ruleset")
	if err != nil {
		return errors.New("firewall_inspection_failed")
	}
	var listing struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(raw, &listing) != nil {
		return errors.New("firewall_inspection_failed")
	}
	for _, object := range listing.NFTables {
		var c struct{ Family, Table, Name, Hook, Policy string }
		if json.Unmarshal(object["chain"], &c) != nil || c.Hook != "input" || c.Policy != "drop" {
			continue
		}
		// Do not insert exceptions into Glivela or other applications' policy.
		// Only the existing independently managed host guard is supported.
		if c.Family != "inet" || c.Table != s.hostGuardTable || c.Name != "input" {
			return errors.New("host_firewall_requires_authorization")
		}
		set := "speed_" + suffix
		transaction := fmt.Sprintf("add set inet %s %s { type %s; flags timeout; timeout 240s; elements = { %s timeout 240s }; }\ninsert rule inet %s %s %s saddr @%s tcp dport { %d, %d, %d, %d } accept comment \"glivela-speed:%s\"\n", c.Table, set, addrType, p.Source, c.Table, c.Name, family, set, speedPort, speedSSPort, speedDownPort, speedSSDownPort, p.ID)
		g := speedGuard{Family: c.Family, Table: c.Table, Chain: c.Name, Set: set}
		s.guards = append(s.guards, g)
		if s.remember() != nil {
			return errors.New("private_intent_failed")
		}
		if speedNFT(ctx, transaction) != nil {
			return errors.New("host_firewall_exception_failed")
		}

		raw, err = speedExec(ctx, "/usr/sbin/nft", "-j", "list", "chain", c.Family, c.Table, c.Name)
		if err != nil {
			return errors.New("host_firewall_inspection_failed")
		}
		var v struct {
			NFTables []struct {
				Rule *struct {
					Handle  int
					Comment string
				} `json:"rule"`
			} `json:"nftables"`
		}
		if json.Unmarshal(raw, &v) != nil {
			return errors.New("host_firewall_inspection_failed")
		}
		for _, x := range v.NFTables {
			if x.Rule != nil && x.Rule.Comment == "glivela-speed:"+p.ID {
				s.guards[len(s.guards)-1].Handle = x.Rule.Handle
			}
		}
		if s.guards[len(s.guards)-1].Handle == 0 {
			return errors.New("host_firewall_ownership_unconfirmed")
		}
	}
	return nil
}
func (s *speedSession) wireBytes() *uint64 {
	bytes, ok := speedNFTStats(s.table)
	if !ok {
		return nil
	}
	return &bytes
}

// The counters cover the actual IP packets for all selected directions.
func speedNFTStats(table string) (uint64, bool) {
	if table == "" {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := speedExec(ctx, "/usr/sbin/nft", "-j", "list", "table", "inet", table)
	if err != nil {
		return 0, false
	}
	var value struct {
		NFTables []struct {
			Counter *struct {
				Name  string `json:"name"`
				Bytes uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if json.Unmarshal(raw, &value) != nil {
		return 0, false
	}
	counters := map[string]uint64{}
	for _, v := range value.NFTables {
		if v.Counter != nil {
			counters[v.Counter.Name] = v.Counter.Bytes
		}
	}
	var total uint64
	for _, spec := range speedPorts {
		count, cok := counters[spec.counter]
		if !cok || ^uint64(0)-total < count {
			return 0, false
		}
		total += count
	}
	return total, true
}
func speedWrite(dir, name string, value []byte) error {
	return os.WriteFile(filepath.Join(dir, name), value, 0600)
}
func (s *speedSession) core(ctx context.Context, config any, name string, port int) error {
	raw, err := json.Marshal(config)
	if err != nil || speedWrite(s.dir, name, raw) != nil {
		return errors.New("temporary_configuration_failed")
	}
	if _, err = speedExec(ctx, s.binary, "run", "-test", "-config", filepath.Join(s.dir, name)); err != nil {
		return errors.New("xray_configuration_rejected")
	}
	process, err := s.start(ctx, s.binary, "run", "-config", filepath.Join(s.dir, name))
	if err != nil {
		return err
	}
	return speedListening(ctx, port, process)
}
func speedListening(ctx context.Context, port int, p *speedProcess) error {
	for i := 0; i < 30; i++ {
		select {
		case <-p.done:
			return errors.New("temporary_listener_failed")
		default:
		}
		raw, err := speedExec(ctx, "ss", "-H", "-lntp", "sport = :"+strconv.Itoa(port))
		if err == nil && bytes.Contains(raw, []byte("pid="+strconv.Itoa(p.cmd.Process.Pid)+",")) {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("test_deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("temporary_listener_failed")
}
func (s *speedSession) execute(parent context.Context, p SpeedAssignment) SpeedReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	report := SpeedReport{ID: p.ID, Role: p.Role}
	if p.Role == "cleanup" || p.Role == "client-cleanup" {
		if s.id != "" && s.id != p.ID {
			report.Error = "cleanup_ownership_changed"
			return report
		}
		report.WireBytes = s.wireBytes()
		err := s.closeLocked()
		report.CleanupConfirmed = err == nil
		if err != nil {
			report.Error = err.Error()
		}
		return report
	}
	if s.id != "" {
		report.Error = "test_resource_busy"
		return report
	}
	step, stop := context.WithTimeout(parent, 15*time.Second)
	defer stop()
	if err := s.prerequisites(step, p); err != nil {
		report.Error = err.Error()
		report.CleanupConfirmed = true
		return report
	}
	dir, err := os.MkdirTemp(s.directory, "speed-")
	if err != nil {
		report.Error = "private_directory_unavailable"
		return report
	}
	s.dir = dir
	s.id = p.ID
	if s.remember() != nil {
		report.Error = "private_intent_failed"
		report.CleanupConfirmed = s.closeLocked() == nil
		return report
	}
	ctx, cancel := context.WithDeadline(parent, p.ExpiresAt)
	s.cancel = cancel
	s.cleanupTimer = time.AfterFunc(time.Until(p.ExpiresAt), func() { _ = s.close() })
	go func() {
		timer := time.NewTicker(500 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				raw, e := os.ReadFile("/proc/meminfo")
				if e != nil {
					cancel()
					return
				}
				var available int64
				for _, line := range strings.Split(string(raw), "\n") {
					if strings.HasPrefix(line, "MemAvailable:") {
						_, _ = fmt.Sscanf(line, "MemAvailable: %d kB", &available)
					}
				}
				if available < 64*1024 {
					cancel()
					return
				}
			}
		}
	}()
	fail := func(err error) SpeedReport {
		report.Error = err.Error()
		if p.Role == "client" {
			for _, mode := range p.Modes {
				if mode == "direct" {
					report.Direct = &SpeedMeasurement{Error: report.Error}
				}
				if mode == "ss2022" {
					report.SS2022 = &SpeedMeasurement{Error: report.Error}
				}
			}
		}
		report.WireBytes = s.wireBytes()
		report.CleanupConfirmed = s.closeLocked() == nil
		return report
	}
	if err = s.firewall(step, p); err != nil {
		return fail(err)
	}
	if speedWrite(dir, "public.pem", []byte(p.PublicKey)) != nil {
		return fail(errors.New("authentication_file_failed"))
	}
	if p.Role == "receiver" {
		network, listen, flag, loopbackCIDR := "tcp4", "0.0.0.0", "-4", "127.0.0.1/32"
		if netip.MustParseAddr(p.Address).Is6() {
			network, listen, flag, loopbackCIDR = "tcp6", "::", "-6", "::1/128"
		}
		for _, port := range []int{speedPort, speedSSPort, speedDownPort, speedSSDownPort} {
			listener, e := net.Listen(network, net.JoinHostPort(listen, strconv.Itoa(port)))
			if e != nil {
				return fail(errors.New("test_port_busy"))
			}
			_ = listener.Close()
		}
		if speedWrite(dir, "private.pem", []byte(p.PrivateKey)) != nil || speedWrite(dir, "users.csv", []byte("speed,"+speedPasswordHash(p.Password)+"\n")) != nil {
			return fail(errors.New("authentication_file_failed"))
		}
		for _, port := range []int{speedPort, speedDownPort} {
			process, e := s.start(ctx, s.iperfBinary, "-s", flag, "-B", listen, "-p", strconv.Itoa(port), "--rsa-private-key-path", filepath.Join(dir, "private.pem"), "--authorized-users-path", filepath.Join(dir, "users.csv"))
			if e != nil {
				return fail(e)
			}
			if e = speedListening(step, port, process); e != nil {
				return fail(e)
			}
		}
		for _, mode := range p.Modes {
			if mode == "ss2022" {
				inbounds := []any{}
				for i, port := range []int{speedSSPort, speedSSDownPort} {
					inbounds = append(inbounds, map[string]any{"tag": []string{"upload", "download"}[i], "listen": listen, "port": port, "protocol": "shadowsocks", "settings": map[string]any{"method": "2022-blake3-aes-128-gcm", "password": p.SSKey, "network": "tcp"}})
				}
				allow := []any{}
				routes := []any{}
				for i, port := range []int{speedPort, speedDownPort} {
					allow = append(allow, map[string]any{"action": "allow", "ip": []string{loopbackCIDR}, "port": strconv.Itoa(port), "network": "tcp"})
					routes = append(routes, map[string]any{"type": "field", "inboundTag": []string{[]string{"upload", "download"}[i]}, "ip": []string{loopbackCIDR}, "port": strconv.Itoa(port), "network": "tcp", "outboundTag": "test"})
				}
				allow = append(allow, map[string]any{"action": "block", "ip": []string{"0.0.0.0/0", "::/0"}})
				config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": inbounds, "outbounds": []any{map[string]any{"tag": "block", "protocol": "blackhole"}, map[string]any{"tag": "test", "protocol": "freedom", "settings": map[string]any{"finalRules": allow}}}, "routing": map[string]any{"domainStrategy": "AsIs", "rules": routes}}
				if e := s.core(ctx, config, "receiver.json", speedSSPort); e != nil {
					return fail(e)
				}
				if e := speedListening(step, speedSSDownPort, s.processes[len(s.processes)-1]); e != nil {
					return fail(e)
				}
			}
		}
		return report
	}
	// Interface binding proves that the public test is not a tailnet/DERP test.
	routeArgs := []string{"-j", "-4", "route", "get", p.Address}
	if netip.MustParseAddr(p.Address).Is6() {
		routeArgs[1] = "-6"
		routeArgs = append(routeArgs, "from", p.Source)
	}
	raw, e := speedExec(step, "ip", routeArgs...)
	var routes []struct {
		Dev string `json:"dev"`
	}
	if e != nil || json.Unmarshal(raw, &routes) != nil || len(routes) != 1 {
		return fail(errors.New("public_route_unavailable"))
	}
	dev := routes[0].Dev
	for _, prefix := range []string{"tailscale", "wg", "tun", "warp"} {
		if strings.HasPrefix(dev, prefix) {
			return fail(errors.New("public_route_uses_tunnel"))
		}
	}
	for _, mode := range p.Modes {
		result := &SpeedMeasurement{}
		if mode == "direct" {
			report.Direct = result
		} else {
			report.SS2022 = result
		}
		if ctx.Err() != nil {
			result.Error = "test_deadline"
			continue
		}
		address := p.Address
		ports := []int{speedPort, speedDownPort}
		if mode == "ss2022" {
			listeners := []net.Listener{}
			ports = []int{}
			for i := 0; i < 2; i++ {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					result.Error = "local_listener_unavailable"
					break
				}
				listeners = append(listeners, listener)
				ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
			}
			for _, listener := range listeners {
				_ = listener.Close()
			}
			if result.Error != "" {
				continue
			}
			address = "127.0.0.1"
			inbounds, outbounds, rules := []any{}, []any{}, []any{}
			for i, tag := range []string{"upload", "download"} {
				targetPort := []int{speedPort, speedDownPort}[i]
				remotePort := []int{speedSSPort, speedSSDownPort}[i]
				loopback := "127.0.0.1"
				outbound := map[string]any{"tag": tag, "protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": p.Address, "port": remotePort, "method": "2022-blake3-aes-128-gcm", "password": p.SSKey}}}, "streamSettings": map[string]any{"sockopt": map[string]any{"interface": dev}}, "mux": map[string]any{"enabled": false}}
				if netip.MustParseAddr(p.Address).Is6() {
					loopback = "::1"
					outbound["sendThrough"] = p.Source
				}
				inbounds = append(inbounds, map[string]any{"tag": tag, "listen": "127.0.0.1", "port": ports[i], "protocol": "dokodemo-door", "settings": map[string]any{"address": loopback, "port": targetPort, "network": "tcp"}})
				outbounds = append(outbounds, outbound)
				rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{tag}, "outboundTag": tag})
			}
			config := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds, "routing": map[string]any{"rules": rules}}
			if e = s.core(ctx, config, "client.json", ports[0]); e != nil {
				result.Error = e.Error()
				continue
			}
			if e = speedListening(ctx, ports[1], s.processes[len(s.processes)-1]); e != nil {
				result.Error = e.Error()
				continue
			}
		}
		for i, reverse := range []bool{false, true} {
			var sample *SpeedSample
			var e error
			if ctx.Err() != nil {
				e = errors.New("test_deadline")
			} else {
				sample, e = s.measure(ctx, p, address, ports[i], dev, reverse, mode == "direct")
			}
			if e != nil {
				if reverse {
					result.DownloadError = e.Error()
				} else {
					result.UploadError = e.Error()
				}
				continue
			}
			if reverse {
				result.Download = sample
			} else {
				result.Upload = sample
			}
		}
	}
	report.WireBytes = s.wireBytes()
	report.CleanupConfirmed = s.closeLocked() == nil
	if !report.CleanupConfirmed {
		report.Error = "client_cleanup_unconfirmed"
	}
	return report
}
func (s *speedSession) measure(parent context.Context, p SpeedAssignment, address string, port int, dev string, reverse, direct bool) (*SpeedSample, error) {
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	defer cancel()
	flag := "-4"
	if netip.MustParseAddr(address).Is6() {
		flag = "-6"
	}
	args := []string{"-c", address, flag, "-p", strconv.Itoa(port), "-t", strconv.Itoa(speedDurationSeconds), "-O", strconv.Itoa(speedWarmupSeconds), "-l", "16384", "-P", "1", "-i", "1", "--connect-timeout", "5000", "--username", "speed", "--rsa-public-key-path", filepath.Join(s.dir, "public.pem"), "--json-stream", "--forceflush", "--get-server-output"}
	if reverse {
		args = append(args, "-R")
	}
	if direct {
		args = append(args, "--bind-dev", dev)
		if flag == "-6" {
			args = append(args, "-B", p.Source)
		}
	}
	cmd := exec.CommandContext(ctx, s.iperfBinary, args...)
	cmd.Env = append(os.Environ(), "IPERF3_PASSWORD="+p.Password)
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.New("iperf_transfer_failed")
	}
	mode, direction := "ss2022", "upload"
	if direct {
		mode = "direct"
	}
	if reverse {
		direction = "download"
	}
	if s.progress != nil {
		s.progress(p.ID, SpeedPoint{Mode: mode, Direction: direction})
	}
	if err = cmd.Start(); err != nil {
		return nil, errors.New("iperf_transfer_failed")
	}
	var end struct {
		Received struct {
			BPS     float64 `json:"bits_per_second"`
			Bytes   int64   `json:"bytes"`
			Seconds float64 `json:"seconds"`
		} `json:"sum_received"`
		Sent struct {
			Retransmits *uint64 `json:"retransmits"`
			Bytes       int64   `json:"bytes"`
		} `json:"sum_sent"`
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	total, sequence := 0, uint32(0)
	seenEnd, invalid := false, false
	for scanner.Scan() {
		line := scanner.Bytes()
		total += len(line)
		if total > 1<<20 {
			invalid = true
			break
		}
		var event struct {
			Event string          `json:"event"`
			Data  json.RawMessage `json:"data"`
		}
		if json.Unmarshal(line, &event) != nil {
			invalid = true
			break
		}
		switch event.Event {
		case "interval":
			var interval struct {
				Sum struct {
					BPS     float64 `json:"bits_per_second"`
					Seconds float64 `json:"seconds"`
					Omitted bool    `json:"omitted"`
				} `json:"sum"`
			}
			if json.Unmarshal(event.Data, &interval) != nil {
				invalid = true
				break
			}
			if !interval.Sum.Omitted && interval.Sum.Seconds > 0 && sequence < 10 {
				sequence++
				if s.progress != nil {
					s.progress(p.ID, SpeedPoint{Mode: mode, Direction: direction, Sequence: sequence, Mbps: interval.Sum.BPS / 1e6, Seconds: interval.Sum.Seconds})
				}
			}
		case "end":
			if json.Unmarshal(event.Data, &end) != nil {
				invalid = true
			} else {
				seenEnd = true
			}
		case "error":
			invalid = true
		}
		if invalid {
			break
		}
	}
	if scanner.Err() != nil {
		invalid = true
	}
	if invalid {
		cancel()
	}
	err = cmd.Wait()
	if invalid {
		return nil, errors.New("iperf_output_invalid")
	}
	if err != nil {
		return nil, errors.New("iperf_transfer_failed")
	}
	if !seenEnd {
		return nil, errors.New("iperf_result_missing")
	}
	r := end.Received
	sample := &SpeedSample{Mbps: r.BPS / 1e6, Bytes: r.Bytes, SentBytes: end.Sent.Bytes, Seconds: r.Seconds, Retransmits: end.Sent.Retransmits}
	if reason := speedSampleError(sample); reason != "" {
		return nil, errors.New(reason)
	}
	return sample, nil
}

// The operator identifies one existing independently managed DROP guard. This
// never discovers a fallback table or authorizes a different hook/family.
func (s *speedSession) loadHostGuard() error {
	path := filepath.Join(s.directory, "host-firewall.json")
	var raw json.RawMessage
	if err := readControlState(path, &raw); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("host_firewall_configuration_invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("host_firewall_configuration_invalid")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	var v struct {
		Version int    `json:"version"`
		Table   string `json:"table"`
	}
	if !ok || owner.Uid != 0 || decode(bytes.NewReader(raw), &v) != nil || v.Version != 1 || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`).MatchString(v.Table) || strings.HasPrefix(v.Table, "glivela_") {
		return errors.New("host_firewall_configuration_invalid")
	}
	s.hostGuardTable = v.Table
	return nil
}
