//go:build linux

package control

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const tcpBudgetKey = "net.ipv4.tcp_mem"
const tcpBudgetFile = "/etc/sysctl.d/99-glivela-tcp-budget.conf"
const tcpBudgetBackupFile = "tcp-memory-budget.json"

type tcpBudgetBackup struct {
	Original  [3]int64 `json:"originalPages"`
	Target    [3]int64 `json:"targetPages"`
	PageBytes int64    `json:"pageBytes"`
	Stage     string   `json:"stage"`
	CommandID string   `json:"commandId"`
	OwnerID   string   `json:"ownerId"`
}

func (b tcpBudgetBackup) save(dir string) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return networkAtomic(filepath.Join(dir, tcpBudgetBackupFile), raw, 0600)
}

func tcpBudgetTier(memory int64) (int64, [3]int64) {
	// MemTotal excludes kernel reservations. Match only the top eighth of a nominal tier.
	for _, tier := range []struct {
		ram    int64
		values [3]int64
	}{
		{512, [3]int64{64, 96, 128}},
		{1024, [3]int64{64, 128, 256}},
		{2048, [3]int64{128, 256, 512}},
	} {
		size := tier.ram << 20
		if memory >= size-size/8 && memory <= size {
			return tier.ram, tier.values
		}
	}
	return 0, [3]int64{}
}

func tcpBudgetPages(mib [3]int64, pageBytes int64) [3]int64 {
	return [3]int64{(mib[0] << 20) / pageBytes, (mib[1] << 20) / pageBytes, (mib[2] << 20) / pageBytes}
}

func tcpBudgetValue(p [3]int64) string {
	return fmt.Sprintf("%d %d %d", p[0], p[1], p[2])
}

func (b tcpBudgetBackup) content() string {
	return fmt.Sprintf("# Managed by Glivela TCP memory budget %x\n%s = %s\n", sha256.Sum256([]byte(b.OwnerID)), tcpBudgetKey, tcpBudgetValue(b.Target))
}

func readTCPBudget() ([3]int64, error) {
	p, err := networkValues(tcpBudgetKey)
	if err != nil || len(p) != 3 || p[0] <= 0 || p[0] > p[1] || p[1] > p[2] {
		return [3]int64{}, errors.New("无法读取 TCP 总预算")
	}
	return [3]int64{p[0], p[1], p[2]}, nil
}

// Only the exact managed file may be restored. An absent file is legitimate
// between saving the original settings and creating/removing the drop-in.
func budgetFileState(b *tcpBudgetBackup) (exists bool, err error) {
	if err = networkAncestry(filepath.Dir(tcpBudgetFile)); err != nil {
		return false, err
	}
	fi, err := os.Lstat(tcpBudgetFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0022 != 0 || fi.Size() > 256 || b == nil || b.Stage == "restored" {
		return false, errors.New("TCP 预算持久配置归属不明")
	}
	uid, err := entryFileUID(fi)
	if err != nil || uid != 0 {
		return false, errors.New("TCP 预算持久配置所有者已变化")
	}
	data, err := os.ReadFile(tcpBudgetFile)
	if err != nil || string(data) != b.content() {
		return false, errors.New("TCP 预算持久配置已被外部修改")
	}
	return true, nil
}

func inspectTCPBudget(dir string, ram int64) *TCPBudgetStatus {
	v := &TCPBudgetStatus{PageBytes: int64(os.Getpagesize())}
	var err error
	v.CurrentPages, err = readTCPBudget()
	if err != nil {
		v.Reason = err.Error()
		return v
	}
	v.TierMiB, v.TargetMiB = tcpBudgetTier(ram)
	b, err := readNetworkBackup[tcpBudgetBackup](dir, tcpBudgetBackupFile)
	if err != nil {
		v.Reason = "无法核验 TCP 预算恢复记录"
		return v
	}
	exists, err := budgetFileState(b)
	if err != nil {
		v.Reason = err.Error()
		return v
	}
	if b != nil && b.Stage != "restored" {
		if b.OwnerID == "" || b.Original[0] <= 0 || b.Original[0] > b.Original[1] || b.Original[1] > b.Original[2] {
			v.Reason = "原始 TCP 预算恢复记录无效"
			return v
		}
		if b.PageBytes != v.PageBytes {
			v.Reason = "内核页大小已变化"
			return v
		}
		switch b.Stage {
		case "applied":
			if !exists || v.CurrentPages != b.Target {
				v.Reason = "已应用的 TCP 预算发生外部变化"
				return v
			}
		case "applying", "restoring":
			if v.CurrentPages != b.Target && v.CurrentPages != b.Original {
				v.Reason = "中断后 TCP 预算发生外部变化"
				return v
			}
			v.Reason = "上次操作中断，可恢复原预算"
		default:
			v.Reason = "TCP 预算恢复记录无效"
			return v
		}
		v.CanRestore = true
		return v
	}
	if v.TierMiB == 0 || v.PageBytes <= 0 || (1<<20)%v.PageBytes != 0 {
		v.Reason = "此内存规格或页大小没有固定档位"
		return v
	}
	v.CanApply = true
	return v
}

func executeTCPBudget(dir string, current NetworkSnapshot, cmd NetworkCommand) error {
	v := current.TCPBudget
	if !current.Observed || v == nil || cmd.ID == "" || len(cmd.ID) > 128 || time.Now().After(cmd.ExpiresAt) {
		return errors.New("需要有效的主机检测和操作请求")
	}
	b, err := readNetworkBackup[tcpBudgetBackup](dir, tcpBudgetBackupFile)
	if err != nil {
		return err
	}
	restore := cmd.Action == "restore-tcp-budget"
	if b != nil && b.CommandID == cmd.ID && ((restore && b.Stage == "restored" && v.CurrentPages == b.Original) || (!restore && b.Stage == "applied" && v.CanRestore)) {
		return nil
	}
	if cmd.Expected != current.Fingerprint || (restore && !v.CanRestore) || (!restore && !v.CanApply) {
		return errors.New("TCP 预算状态已变化，请重新检测")
	}
	if restore {
		if b == nil {
			return errors.New("缺少原始 TCP 预算")
		}
		b.Stage = "restoring"
		b.CommandID = cmd.ID
	} else {
		b = &tcpBudgetBackup{Original: v.CurrentPages, Target: tcpBudgetPages(v.TargetMiB, v.PageBytes), PageBytes: v.PageBytes, Stage: "applying", CommandID: cmd.ID, OwnerID: cmd.ID}
	}
	if err = b.save(dir); err != nil {
		return err
	}
	exists, err := budgetFileState(b)
	if err != nil {
		return err
	}
	want := b.Target
	if restore {
		want = b.Original
	} else {
		if exists {
			return errors.New("TCP 预算持久配置已存在")
		}
		if err = writeNetworkFile(tcpBudgetFile, []byte(b.content()), 0644, false); err != nil {
			return err
		}
	}
	before, err := readTCPBudget()
	if err != nil || before != v.CurrentPages {
		return errors.New("TCP 预算在应用前已变化")
	}
	if before != want {
		if err = networkWrite(tcpBudgetKey, tcpBudgetValue(want)); err != nil {
			return err
		}
	}
	actual, err := readTCPBudget()
	if err != nil || actual != want {
		return errors.New("TCP 预算读回不一致，已保留恢复记录")
	}
	exists, err = budgetFileState(b)
	if err != nil {
		return err
	}
	if restore {
		if exists {
			if err = os.Remove(tcpBudgetFile); err != nil {
				return err
			}
		}
		b.Stage = "restored"
	} else {
		if !exists {
			return errors.New("TCP 预算持久配置未读回")
		}
		b.Stage = "applied"
	}
	return b.save(dir)
}
