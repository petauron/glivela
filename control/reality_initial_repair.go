package control

import (
	"net"
	"reflect"
	"slices"
	"time"

	glivela "github.com/petauron/glivela"
)

// This identifies a narrowly repairable registration, not proof that a worker
// never ran. An administrator must separately verify the authenticated host,
// stop its worker, inspect its activation journal and retain that evidence.
func (s *Store) initialRealityTargetRepairable(node Node, e glivela.ImportEndpoint, now time.Time) bool {
	if e.DesiredRevision != 1 || e.AppliedRevision != 0 || e.PreviousStatus != "pending" || e.HistoricalHealthy || e.LegacyRetired || e.Retired || e.RuntimeCertificateID != "" || e.RuntimeConfigSHA256 != "" || e.PreviousAdvertiseHost != "" || len(e.RealityChanges) != 0 || !e.VLESSEnabled || e.Hysteria != nil || e.HysteriaEnabled || e.TotalBytes != 0 || e.UsedBytes != 0 || e.ResetDay != 0 || !e.QuotaAppliedEnabled {
		return false
	}
	host, port, err := net.SplitHostPort(e.Reality.Target)
	if err != nil || e.TargetIP != "127.0.0.1" || port == "24483" || len(e.Reality.ServerNames) != 1 || host != e.Reality.ServerNames[0] || !glivela.ValidRealityTargetPin(net.JoinHostPort(host, "24483"), e.TargetIP) {
		return false
	}
	if node.Desired.Revision != 1 || node.Desired.Entry == nil || node.Desired.EntryNetwork == nil || node.Receipt != nil || node.TransportPrevious != nil || node.TransportTail != nil || node.EntryQuota != nil || len(node.Checks) != 0 || len(node.RouteEntries) != 0 {
		return false
	}
	plan, network := node.Desired.Entry, node.Desired.EntryNetwork
	if len(plan.RealityEndpoints) != 1 || len(plan.HysteriaEndpoints) != 0 || len(plan.Grants) != 0 || len(plan.Peers) != 0 || network.Source != nil || len(network.Peers) != 0 || len(network.SpeedPeers) != 0 || !realityNodeMatches(node, e) {
		return false
	}
	if s.suspended(node.ID, now) {
		pause, ok := s.effectiveAvailability(node.ID)
		if !ok || pause.Reason != "maintenance" {
			return false
		}
	}
	if node.Network != nil && node.Network.Command != nil && now.Before(node.Network.Command.ExpiresAt) && (node.Network.Result == nil || node.Network.Result.ID != node.Network.Command.ID) {
		return false
	}
	if s.speedFault {
		return false
	}
	for _, job := range s.speedJobs {
		if job.Request.EntryID == node.ID && !job.View.CleanupConfirmed && now.Before(job.View.StartedAt.Add(speedLease+15*time.Second)) {
			return false
		}
	}
	m := s.business.material
	if m.References.Applications[node.ID].Runtime != "host" || slices.ContainsFunc(m.ClientChains, func(c glivela.ClientChain) bool { return c.EntryID == node.ID }) {
		return false
	}
	credentials := 0
	for _, account := range m.Plan.Accounts {
		for _, grant := range account.Grants {
			if grant.EntryID == node.ID {
				return false
			}
		}
		for _, credential := range account.Credentials {
			if credential.EntryID != node.ID {
				continue
			}
			credentials++
			counter, exists := m.TrafficCounters[credential.ID]
			if credential.Kind != glivela.NativeCredential || !exists || counter != (glivela.ImportTrafficCounters{}) {
				return false
			}
			usage := slices.IndexFunc(account.Usage, func(u glivela.UsageMember) bool { return u.CredentialID == credential.ID })
			if usage < 0 || account.Usage[usage].Baseline != 0 || account.Usage[usage].Observed != 0 {
				return false
			}
		}
	}
	// No hidden or stale credentials or policy may be changed by the repair.
	expected, _, err := projectBusinessEntries(s.nodes, m, now)
	return err == nil && credentials > 0 && credentials == len(plan.Credentials) && reflect.DeepEqual(expected, s.nodes)
}
