//go:build linux

package control

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const budgetHostSocket = "/run/vastora-tcp-budget/control.sock"

type hostBudgetRequest struct {
	Action   string    `json:"action"`
	Expected string    `json:"expected,omitempty"`
	ID       string    `json:"id,omitempty"`
	Expires  time.Time `json:"expiresAt,omitzero"`
}

func requestHostBudget(req hostBudgetRequest) (*TCPBudgetStatus, error) {
	if err := networkAncestry(filepath.Dir(budgetHostSocket)); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(budgetHostSocket)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0600 || fi.Sys().(*syscall.Stat_t).Uid != 0 {
		return nil, errors.New("缺少受管主机 TCP 预算操作")
	}
	c, err := net.DialTimeout("unix", budgetHostSocket, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if err = json.NewEncoder(c).Encode(req); err != nil {
		return nil, err
	}
	if err = c.(*net.UnixConn).CloseWrite(); err != nil {
		return nil, err
	}
	var result struct {
		Status *TCPBudgetStatus `json:"status"`
		Error  string           `json:"error"`
	}
	data, e := io.ReadAll(io.LimitReader(c, 2049))
	if e != nil || len(data) > 2048 || json.Unmarshal(data, &result) != nil || result.Error != "" || result.Status == nil || len(result.Status.Revision) != 64 {
		return nil, errors.New("主机未授权、状态已变化或操作失败；请重新检测")
	}
	return result.Status, nil
}

func inspectTCPBudget(dir string, _ int64) *TCPBudgetStatus {
	v := &TCPBudgetStatus{PageBytes: int64(os.Getpagesize())}
	p, e := networkValues("net.ipv4.tcp_mem")
	if e != nil || len(p) != 3 {
		v.Reason = "无法读取 TCP 总预算"
		return v
	}
	copy(v.CurrentPages[:], p)
	// A pre-broker recovery record still belongs to the original writer. Never
	// adopt its supplied pages or replace its drop-in from the privileged host.
	old, e := readNetworkBackup[struct {
		Stage string `json:"stage"`
	}](dir, "tcp-memory-budget.json")
	if e != nil || old != nil && old.Stage != "restored" {
		v.Reason = "旧 TCP 预算恢复记录尚未收尾"
		return v
	}
	status, e := requestHostBudget(hostBudgetRequest{Action: "inspect"})
	if e != nil {
		v.Reason = "主机未提供已授权的 TCP 预算操作，只能查看"
		return v
	}
	if status.CurrentPages != v.CurrentPages || status.PageBytes != v.PageBytes {
		v.Reason = "主机与节点读回不一致"
		return v
	}
	return status
}

func executeTCPBudget(_ string, current NetworkSnapshot, c NetworkCommand) error {
	v := current.TCPBudget
	restore := c.Action == "restore-tcp-budget"
	if !current.Observed || v == nil || v.Revision == "" || c.Expected != current.Fingerprint || c.ID == "" || len(c.ID) > 128 || !time.Now().Before(c.ExpiresAt) || restore && !v.CanRestore || !restore && (c.Action != "apply-tcp-budget" || !v.CanApply) {
		return errors.New("主机 TCP 预算不可用或状态已变化，请重新检测")
	}
	action := "apply"
	if restore {
		action = "restore"
	}
	after, e := requestHostBudget(hostBudgetRequest{Action: action, Expected: v.Revision, ID: c.ID, Expires: c.ExpiresAt})
	if e != nil {
		return e
	}
	p, e := networkValues("net.ipv4.tcp_mem")
	if e != nil || len(p) != 3 || [3]int64(p) != after.CurrentPages || restore && after.CanRestore || !restore && !after.CanRestore {
		return errors.New("主机 TCP 预算未通过独立读回")
	}
	return nil
}
