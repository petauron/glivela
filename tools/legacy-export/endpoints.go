package main

import (
	"encoding/json"
	"errors"

	glivela "github.com/petauron/glivela"
)

func (r *record) jsonBytes(name string) []byte {
	v, ok := r.fields[name]
	if !ok {
		r.err = errors.New("required JSON missing")
		return nil
	}
	var raw []byte
	switch v.Kind {
	case "blob":
		raw = append([]byte{}, v.Blob...)
	case "text":
		raw = []byte(v.Text)
	default:
		r.err = errors.New("invalid JSON storage class")
		return nil
	}
	if !json.Valid(raw) {
		r.err = errors.New("invalid stored JSON")
		return nil
	}
	return raw
}

func (r *record) strings(name string) []string {
	var values []string
	if json.Unmarshal(r.jsonBytes(name), &values) != nil {
		r.err = errors.New("invalid stored string array")
	}
	return values
}

func (r *record) port(name string) int {
	n := r.integer(name)
	if n > 65535 {
		r.err = errors.New("invalid port")
		return 0
	}
	return int(n)
}

// endpointMaterial copies the full recorded configuration, including disabled
// protocols and historical failed states. It never probes, chooses a new key,
// regenerates certificates or turns an old healthy flag into a fresh receipt.
func endpointMaterial(a archive) ([]glivela.ImportEndpoint, error) {
	rows, err := records(a, "meridian_endpoints")
	if err != nil {
		return nil, err
	}
	result := make([]glivela.ImportEndpoint, 0, len(rows))
	for _, r := range rows {
		id := r.text("id")
		day := r.integer("reset_day")
		if day > 31 {
			return nil, errors.New("invalid endpoint reset day")
		}
		endpoint := glivela.ImportEndpoint{
			Reality: glivela.RealityEndpoint{ID: id, EntryID: r.text("application_id"), InboundTag: r.text("inbound_tag"),
				ListenAddress: r.text("listen_address"), ListenPort: r.port("listen_port"), AdvertiseHost: r.text("advertise_host"), AdvertisePort: r.port("advertise_port"),
				Target: r.text("target"), ServerNames: r.strings("server_names_json"), PrivateKey: r.secret(a, "private_key_secret_id", "meridian-endpoint:"+id, false), PublicKey: r.text("public_key"), ShortIDs: r.strings("short_ids_json"), Fingerprint: r.text("fingerprint")},
			ServiceID: r.text("service_id"), TargetIP: r.text("target_ip"), VLESSEnabled: r.boolean("vless_enabled"), HysteriaEnabled: r.boolean("hy2_enabled"),
			TotalBytes: r.integer("total_bytes"), UsedBytes: r.integer("used_bytes"), QuotaAppliedEnabled: r.boolean("quota_applied_enabled"), ResetDay: int(day),
			ResetSchedule:   glivela.ImportResetSchedule{NextResetAt: r.text("next_reset_at"), LastResetAt: r.text("last_reset_at")},
			DesiredRevision: uint64(r.integer("desired_revision")), AppliedRevision: uint64(r.integer("applied_revision")), HistoricalHealthy: r.boolean("runtime_healthy"),
			PreviousStatus: r.text("status"), PreviousError: r.text("last_error"), LegacyRetired: r.boolean("legacy_retired"), SourcePeerJSON: r.jsonBytes("source_peer_json"),
			CertificateNotAfter: r.text("hy2_certificate_not_after"), CreatedAt: r.text("created_at"), UpdatedAt: r.text("updated_at"),
		}
		hy2Tag := r.text("hy2_inbound_tag")
		if hy2Tag != "" {
			endpoint.Hysteria = &glivela.HysteriaEndpoint{ID: id + "-hy2", EntryID: endpoint.Reality.EntryID, InboundTag: hy2Tag, ListenPort: 443,
				AdvertiseHost: endpoint.Reality.AdvertiseHost, AdvertisePort: 443, ServerName: r.text("hy2_server_name"),
				CertificatePEM: r.secret(a, "hy2_certificate_secret_id", "meridian-hy2-certificate:"+id, false), PrivateKeyPEM: r.secret(a, "hy2_private_key_secret_id", "meridian-hy2-private-key:"+id, false)}
		} else {
			// No hidden configured material may be silently discarded just because
			// the protocol is currently disabled or its tag is empty.
			if r.text("hy2_server_name") != "" || r.optionalText("hy2_certificate_secret_id") != "" || r.optionalText("hy2_private_key_secret_id") != "" {
				return nil, errors.New("inconsistent stored Hysteria configuration")
			}
		}
		if r.err != nil || endpoint.Validate() != nil {
			return nil, errors.New("invalid stored endpoint configuration")
		}
		result = append(result, endpoint)
	}
	return result, nil
}
