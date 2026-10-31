package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"time"

	glivela "github.com/petauron/glivela"
)

func nodeStateHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func encodedNodes(nodes map[string]Node) ([]byte, error) {
	values := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		values = append(values, n)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return json.Marshal(values)
}

// Bind only the already-enrolled runtime in this exclusively locked directory.
// Source DB configuration remains intact in RetainedSource. A staged pilot may
// have replaced its old fixed-IP decoy with the recorded SNI hostname; preserve
// that actual configuration, never resolve/select a replacement during import.
func bindExistingBusinessRuntime(s *Store, m *glivela.ImportMaterial) error {
	for _, node := range s.nodes {
		if node.Desired.Entry == nil {
			continue
		}
		for _, actual := range node.Desired.Entry.RealityEndpoints {
			i := slices.IndexFunc(m.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.ID == actual.ID && e.Reality.EntryID == node.ID })
			if i < 0 {
				return errors.New("control: enrolled entry missing from business snapshot")
			}
			e := &m.Endpoints[i]
			expected := e.Reality
			expected.Target = actual.Target
			host, port, err := net.SplitHostPort(actual.Target)
			if !reflect.DeepEqual(expected, actual) || err != nil || port != "443" || !slices.Contains(e.Reality.ServerNames, host) && host != e.TargetIP {
				return errors.New("control: enrolled REALITY identity differs from business snapshot")
			}
			e.Reality = actual
			e.TargetIP = ""
			e.RuntimeCertificateID = node.CertificateID
			e.RuntimeConfigSHA256 = node.Desired.ConfigSHA256
		}
	}
	return m.Validate()
}

// Validate the retained quota against the final persisted business policy. Raw
// samples may have advanced after the old writer stopped; the account baseline
// remains the final imported watermark and the next ordinary sample adds only
// its delta. No forced tail sampling, counters reset or desired-state replay.
func prepareBusinessNodes(s *Store, m glivela.ImportMaterial) (map[string]Node, bool, error) {
	next := s.copy()
	changed := false
	for cert, node := range next {
		if node.EntryQuota == nil {
			continue
		}
		q := node.EntryQuota
		i := slices.IndexFunc(m.Endpoints, func(e glivela.ImportEndpoint) bool { return e.Reality.EntryID == node.ID })
		if i < 0 {
			return nil, false, errors.New("control: quota entry has no imported business")
		}
		e := m.Endpoints[i]
		if e.RuntimeCertificateID != cert || e.RuntimeConfigSHA256 != node.Desired.ConfigSHA256 || q.TotalBytes != e.TotalBytes || q.ResetDay != e.ResetDay || q.ResetDay > 0 && q.Timezone != m.References.Services[e.ServiceID].Timezone || q.TotalBytes > 0 && q.UsedBytes < e.UsedBytes {
			return nil, false, errors.New("control: staged quota ownership or policy differs")
		}
		if !sameOptionalTime(q.LastResetAt, e.ResetSchedule.LastResetAt) || !sameOptionalTime(q.NextResetAt, e.ResetSchedule.NextResetAt) {
			return nil, false, errors.New("control: staged quota cycle differs")
		}
		for _, c := range q.Base.Entry.Credentials {
			found := false
			for _, a := range m.Plan.Accounts {
				for _, want := range a.Credentials {
					if c.Credential.ID == want.ID {
						found = sameCredentialIdentity(c, glivela.CredentialMaterial{Credential: want, ProtocolID: m.ProtocolSecrets[want.ID], HysteriaAuth: m.HysteriaSecrets[want.ID], HysteriaIdentity: glivela.Identity(m.HysteriaSecrets[want.ID])})
					}
				}
			}
			if !found {
				return nil, false, errors.New("control: staged quota credential differs")
			}
		}
		node.EntryQuota = nil
		next[cert] = node
		changed = true
	}
	return next, changed, nil
}

func sameOptionalTime(t time.Time, s string) bool {
	if s == "" {
		return t.IsZero()
	}
	v, e := time.Parse(time.RFC3339Nano, s)
	return e == nil && t.Equal(v)
}

// The owned business file is committed first. A crash before the node-file
// transition keeps startup fenced; repeating the offline adoption completes
// only these exact source/target hashes. An applied marker prevents replaying
// a restored old quota file over an already-running owned ledger.
func finishBusinessNodes(directory string, intent businessAdoptionIntent, m glivela.ImportMaterial) error {
	s, err := OpenStore(filepath.Join(directory, "nodes.json"))
	if err != nil {
		return err
	}
	marker := filepath.Join(directory, "business.nodes.applied.json")
	if info, err := os.Lstat(marker); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
			return errors.New("control: unsafe node handover acknowledgement")
		}
		raw, err := os.ReadFile(marker)
		var got businessAdoptionIntent
		if err != nil || decode(bytes.NewReader(raw), &got) != nil || got != intent {
			return errors.New("control: node handover acknowledgement differs")
		}
		for _, n := range s.nodes {
			if n.EntryQuota != nil {
				return errors.New("control: retired quota state was restored")
			}
		}
		return syncBusinessDirectory(directory)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if intent.NodesBeforeSHA256 == "" {
		for _, n := range s.nodes {
			if n.EntryQuota != nil {
				return errors.New("control: unbound staged quota cannot be adopted")
			}
		}
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	current := nodeStateHash(raw)
	if current == intent.NodesBeforeSHA256 {
		next, changed, err := prepareBusinessNodes(s, m)
		if err != nil || !changed {
			return errors.New("control: quota handover source differs")
		}
		target, err := encodedNodes(next)
		if err != nil || nodeStateHash(target) != intent.NodesAfterSHA256 {
			return errors.New("control: quota handover target differs")
		}
		if err := s.commit(next); err != nil {
			return err
		}
	} else if current != intent.NodesAfterSHA256 {
		return errors.New("control: node state changed during business handover")
	}
	raw, err = os.ReadFile(s.path)
	if err != nil || nodeStateHash(raw) != intent.NodesAfterSHA256 {
		return errors.New("control: node handover durability check failed")
	}
	proof, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	return writeNewBusinessFile(directory, "business.nodes.applied.json", proof)
}
