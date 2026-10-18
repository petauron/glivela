package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strconv"

	glivela "github.com/petauron/glivela"
	"github.com/petauron/glivela/control"
)

func stageImportCommand(args []string) error {
	flags := flag.NewFlagSet("stage", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("archive", "", "private encrypted offline archive")
	snapshot := flags.String("snapshot", "", "expected snapshot identity")
	directory := flags.String("state-directory", "", "offline controller state directory")
	transferPath := flags.String("transfer-key", "", "private 32-byte transfer key file")
	storagePath := flags.String("storage-key", "", "independent private controller storage key file")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("invalid staging arguments")
	}
	transfer, err := privateFile(*transferPath, 32)
	if err != nil || len(transfer) != 32 {
		return errors.New("invalid transfer key")
	}
	defer clear(transfer)
	storage, err := privateFile(*storagePath, 32)
	if err != nil || len(storage) != 32 || bytes.Equal(transfer, storage) {
		return errors.New("independent storage key required")
	}
	defer clear(storage)
	sealed, err := privateFile(*input, maxSnapshotBytes+64)
	if err != nil {
		return err
	}
	a, err := openArchive(sealed, transfer, *snapshot)
	if err != nil {
		return err
	}
	defer func() {
		for _, secret := range a.Secrets {
			clear(secret.Value)
		}
	}()
	material, err := importMaterial(a)
	if err != nil {
		return err
	}
	sealedImport, err := glivela.SealImportMaterial(material, transfer, *snapshot)
	if err != nil {
		return err
	}
	return control.StageImport(*directory, *snapshot, sealedImport, transfer, storage)
}

func openArchive(sealed, key []byte, snapshot string) (archive, error) {
	var a archive
	if !glivela.ValidIdentifier(snapshot) || len(key) != 32 || len(sealed) > maxSnapshotBytes+64 {
		return a, errors.New("invalid archive identity or size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return a, err
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return a, err
	}
	raw, err := gcm.Open(nil, nil, sealed, []byte(archiveContext+snapshot))
	if err != nil {
		return a, errors.New("archive authentication failed")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&a) != nil || decoder.Decode(&extra) != io.EOF || a.Version != 1 || a.Schema != supportedSchema || a.SnapshotID != snapshot || !glivela.ValidIdentity(a.SourceSHA256) || len(a.Tables) != len(businessTables) {
		return archive{}, errors.New("invalid archive")
	}
	for _, name := range businessTables {
		if _, ok := a.Tables[name]; !ok {
			return archive{}, errors.New("incomplete archive")
		}
	}
	return a, nil
}

// record reads the fixed legacy schema without coercing NULL into an ID or
// rounding SQLite integers. The first structural error aborts the conversion.
type record struct {
	fields map[string]cell
	err    error
}

func records(a archive, name string) ([]*record, error) {
	t, ok := a.Tables[name]
	if !ok || len(t.Columns) == 0 || len(t.Columns) > 256 {
		return nil, errors.New("missing legacy table")
	}
	seen := map[string]bool{}
	for _, column := range t.Columns {
		if column == "" || seen[column] {
			return nil, errors.New("invalid legacy columns")
		}
		seen[column] = true
	}
	result := make([]*record, 0, len(t.Rows))
	for _, row := range t.Rows {
		if len(row) != len(t.Columns) {
			return nil, errors.New("invalid legacy row")
		}
		r := &record{fields: map[string]cell{}}
		for i, column := range t.Columns {
			r.fields[column] = row[i]
		}
		result = append(result, r)
	}
	return result, nil
}

func (r *record) text(name string) string {
	v, ok := r.fields[name]
	if !ok || v.Kind != "text" {
		r.err = errors.New("required text missing")
		return ""
	}
	return v.Text
}
func (r *record) optionalText(name string) string {
	if v, ok := r.fields[name]; ok && v.Kind == "null" {
		return ""
	}
	value := r.text(name)
	if value == "" {
		r.err = errors.New("nullable identity must be NULL or nonempty text")
	}
	return value
}
func (r *record) integer(name string) int64 {
	v, ok := r.fields[name]
	n, err := strconv.ParseInt(v.Text, 10, 64)
	if !ok || v.Kind != "integer" || err != nil || n < 0 {
		r.err = errors.New("required nonnegative integer missing")
		return 0
	}
	return n
}
func (r *record) boolean(name string) bool {
	n := r.integer(name)
	if n > 1 {
		r.err = errors.New("invalid boolean")
	}
	return n == 1
}
func (r *record) secret(a archive, column, aad string, optional bool) string {
	var id string
	if optional {
		id = r.optionalText(column)
	} else {
		id = r.text(column)
	}
	if optional && id == "" {
		return ""
	}
	s, ok := a.Secrets[id]
	if !ok || s.Context != aad || len(s.Value) == 0 {
		r.err = errors.New("secret identity missing")
		return ""
	}
	return string(s.Value)
}

func importMaterial(a archive) (glivela.ImportMaterial, error) {
	m := glivela.ImportMaterial{
		SubscriptionTokens: map[string]string{}, ProtocolSecrets: map[string]string{}, HysteriaSecrets: map[string]string{},
		ResetSchedules: map[string]glivela.ImportResetSchedule{}, TrafficCounters: map[string]glivela.ImportTrafficCounters{},
	}
	endpoints, err := records(a, "meridian_endpoints")
	if err != nil {
		return m, err
	}
	type endpoint struct{ entry, tag string }
	byEndpoint := map[string]endpoint{}
	for _, r := range endpoints {
		id := r.text("id")
		value := endpoint{r.text("application_id"), r.text("inbound_tag")}
		if _, ok := byEndpoint[id]; ok || r.err != nil || !glivela.ValidIdentifier(id) || !glivela.ValidIdentifier(value.entry) {
			return m, errors.New("invalid endpoint identity")
		}
		byEndpoint[id] = value
	}
	accounts, err := records(a, "meridian_accounts")
	if err != nil {
		return m, err
	}
	items := make([]glivela.ImportAccount, 0, len(accounts))
	byAccount := map[string]int{}
	for _, r := range accounts {
		id := r.text("id")
		resetDays := r.integer("reset_days")
		if resetDays > glivela.MaxResetDays {
			return m, errors.New("invalid account reset period")
		}
		item := glivela.ImportAccount{Account: glivela.Account{ID: id, DisplayName: r.text("display_name"),
			Plan:            glivela.AccountPlan{TotalBytes: r.integer("total_bytes"), ExpiryTime: r.integer("expiry_time"), ResetDays: int(resetDays), Enabled: r.boolean("enabled")},
			DesiredRevision: uint64(r.integer("desired_revision")), AppliedRevision: uint64(r.integer("applied_revision"))},
			SubscriptionTokenFingerprint: r.text("subscription_token_sha256"), HysteriaIdentities: map[string]string{},
		}
		m.SubscriptionTokens[id] = r.secret(a, "subscription_token_secret_id", "meridian-account:"+id, false)
		m.ResetSchedules[id] = glivela.ImportResetSchedule{NextResetAt: r.text("next_reset_at"), LastResetAt: r.text("last_reset_at")}
		if _, ok := byAccount[id]; ok || r.err != nil || item.Account.Validate() != nil {
			return m, errors.New("invalid account record")
		}
		byAccount[id] = len(items)
		items = append(items, item)
	}
	credentials, err := records(a, "meridian_credentials")
	if err != nil {
		return m, err
	}
	byCredential := map[string]glivela.Credential{}
	for _, r := range credentials {
		id, account, endpointID := r.text("id"), r.text("account_id"), r.text("endpoint_id")
		i, ok := byAccount[account]
		ep, hasEndpoint := byEndpoint[endpointID]
		c := glivela.Credential{ID: id, AccountID: account, Kind: glivela.CredentialKind(r.text("kind")), User: r.text("user_name"), Identity: r.text("identity_sha256"), EntryID: ep.entry, EgressID: r.optionalText("egress_node_id"), Enabled: r.boolean("enabled")}
		m.ProtocolSecrets[id] = r.secret(a, "protocol_secret_id", "meridian-credential:"+id, false)
		hy2 := r.secret(a, "hy2_auth_secret_id", "meridian-credential-hy2:"+id, true)
		hy2Identity := r.text("hy2_identity_sha256")
		_, duplicate := byCredential[id]
		if r.err != nil || !ok || !hasEndpoint || duplicate || c.Validate() != nil || glivela.Identity(hy2) != hy2Identity {
			return m, errors.New("invalid credential record")
		}
		if hy2 != "" {
			m.HysteriaSecrets[id] = hy2
			items[i].HysteriaIdentities[id] = hy2Identity
		}
		byCredential[id] = c
		items[i].Credentials = append(items[i].Credentials, c)
	}
	watermarks, err := records(a, "meridian_usage_watermarks")
	if err != nil {
		return m, err
	}
	for _, r := range watermarks {
		id := r.text("credential_id")
		c, ok := byCredential[id]
		_, duplicate := m.TrafficCounters[id]
		usage := glivela.UsageMember{CredentialID: id, Baseline: r.integer("baseline_bytes"), Observed: r.integer("observed_bytes"), Active: c.Enabled}
		m.TrafficCounters[id] = glivela.ImportTrafficCounters{RawUploadBytes: r.integer("raw_up_bytes"), RawDownloadBytes: r.integer("raw_down_bytes"), WatermarkObservedAt: r.text("observed_at")}
		if r.err != nil || !ok || duplicate {
			return m, errors.New("invalid usage watermark")
		}
		i := byAccount[c.AccountID]
		items[i].Usage = append(items[i].Usage, usage)
	}
	lines, err := records(a, "meridian_line_usage")
	if err != nil {
		return m, err
	}
	seenLines := map[string]bool{}
	for _, r := range lines {
		id := r.text("credential_id")
		counter, ok := m.TrafficCounters[id]
		counter.UploadBytes = r.integer("upload_bytes")
		counter.DownloadBytes = r.integer("download_bytes")
		counter.StartedAt = r.text("started_at")
		counter.ObservedAt = r.text("observed_at")
		if r.err != nil || !ok || seenLines[id] {
			return m, errors.New("invalid directional usage")
		}
		seenLines[id] = true
		m.TrafficCounters[id] = counter
	}
	grants, err := records(a, "meridian_route_grants")
	if err != nil {
		return m, err
	}
	for _, r := range grants {
		account := r.text("account_id")
		i, ok := byAccount[account]
		ep, hasEndpoint := byEndpoint[r.text("endpoint_id")]
		base, hasBase := byCredential[r.text("base_credential_id")]
		routed, hasRoute := byCredential[r.text("route_credential_id")]
		g := glivela.RouteGrant{ID: r.text("id"), AccountID: account, EntryID: ep.entry, EgressID: r.text("egress_node_id"), IPv4EgressID: r.optionalText("ipv4_egress_node_id"), InboundTag: ep.tag, Base: base, Route: routed,
			Mode: glivela.PublishingMode(r.text("mode")), HideNative: r.boolean("hide_native"), Enabled: r.boolean("enabled"), DesiredRev: uint64(r.integer("desired_revision")), AppliedRev: uint64(r.integer("applied_revision")), RuntimeGood: r.boolean("runtime_healthy")}
		if r.err != nil || !ok || !hasEndpoint || !hasBase || !hasRoute || g.Validate() != nil {
			return m, errors.New("invalid route record")
		}
		items[i].Grants = append(items[i].Grants, g)
	}
	m.Plan, err = glivela.PlanImport(items)
	if err != nil {
		return m, err
	}
	m.Endpoints, err = endpointMaterial(a)
	if err != nil {
		return m, err
	}
	m.SourceSHA256 = a.SourceSHA256
	m.RetainedSource, err = json.Marshal(a)
	if err != nil {
		return m, errors.New("source retention failed")
	}
	return m, m.Validate()
}
