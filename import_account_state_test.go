package glivela

import "testing"

func TestImportAccountStateRequiresExactInventory(t *testing.T) {
	for name, change := range map[string]func(*ImportMaterial){
		"missing schedule": func(m *ImportMaterial) { delete(m.ResetSchedules, "account-a") },
		"orphan schedule":  func(m *ImportMaterial) { m.ResetSchedules["other"] = ImportResetSchedule{} },
		"wrong account": func(m *ImportMaterial) {
			delete(m.ResetSchedules, "account-a")
			m.ResetSchedules["other"] = ImportResetSchedule{}
		},
		"invalid next reset": func(m *ImportMaterial) {
			s := m.ResetSchedules["account-a"]
			s.NextResetAt = "tomorrow"
			m.ResetSchedules["account-a"] = s
		},
		"invalid last reset": func(m *ImportMaterial) {
			s := m.ResetSchedules["account-a"]
			s.LastResetAt = "yesterday"
			m.ResetSchedules["account-a"] = s
		},
		"missing counters": func(m *ImportMaterial) { delete(m.TrafficCounters, "native-a") },
		"orphan counters":  func(m *ImportMaterial) { m.TrafficCounters["other"] = ImportTrafficCounters{} },
	} {
		t.Run(name, func(t *testing.T) {
			m := importFixture(t)
			change(&m)
			if m.Validate() == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
	for _, field := range []string{"upload", "download", "rawUpload", "rawDownload", "started", "observed", "watermark"} {
		t.Run(field, func(t *testing.T) {
			m := importFixture(t)
			c := m.TrafficCounters["native-a"]
			switch field {
			case "upload":
				c.UploadBytes = -1
			case "download":
				c.DownloadBytes = -1
			case "rawUpload":
				c.RawUploadBytes = -1
			case "rawDownload":
				c.RawDownloadBytes = -1
			case "started":
				c.StartedAt = "invalid"
			case "observed":
				c.ObservedAt = "invalid"
			case "watermark":
				c.WatermarkObservedAt = "invalid"
			}
			m.TrafficCounters["native-a"] = c
			if m.Validate() == nil {
				t.Fatal("invalid traffic state accepted")
			}
		})
	}
}

func TestImportAccountStatePreservesUnknownTimestamps(t *testing.T) {
	m := importFixture(t)
	m.ResetSchedules["account-a"] = ImportResetSchedule{}
	m.TrafficCounters["native-a"] = ImportTrafficCounters{}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
}
