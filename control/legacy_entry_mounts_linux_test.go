package control

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyEntryRetainsOnlyPinnedImageVolumes(t *testing.T) {
	fixture := `{"Mounts":[{"Type":"bind","Source":"/private/example","Destination":"/etc/vastora","RW":false},{"Type":"volume","Source":"/var/lib/docker/volumes/` + strings.Repeat("a", 64) + `/_data","Destination":"/var/log/xray","RW":true},{"Type":"volume","Source":"/var/lib/docker/volumes/` + strings.Repeat("b", 64) + `/_data","Destination":"/usr/local/etc/xray","RW":true}]}`
	for _, scenario := range []string{"image volumes", "config only", "unknown destination", "extra bind", "named volume", "outside docker", "duplicate destination", "partial volumes", "writable config"} {
		t.Run(scenario, func(t *testing.T) {
			var state entryContainerState
			if err := json.Unmarshal([]byte(fixture), &state); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "config only":
				state.Mounts = state.Mounts[:1]
			case "unknown destination":
				state.Mounts[1].Destination = "/etc/unknown"
			case "extra bind":
				state.Mounts[1].Type = "bind"
			case "named volume":
				state.Mounts[1].Source = "/var/lib/docker/volumes/user-data/_data"
			case "outside docker":
				state.Mounts[1].Source = "/another/volumes/" + strings.Repeat("a", 64) + "/_data"
			case "duplicate destination":
				state.Mounts[2].Destination = state.Mounts[1].Destination
			case "partial volumes":
				state.Mounts = state.Mounts[:2]
			case "writable config":
				state.Mounts[0].RW = true
			}
			before, _ := json.Marshal(state)
			want := scenario == "image volumes" || scenario == "config only"
			if legacyEntryMountsValid(state) != want {
				t.Fatal("unexpected mount ownership verdict")
			}
			after, _ := json.Marshal(state)
			if string(before) != string(after) {
				t.Fatal("validation changed retained mount evidence")
			}
		})
	}
}
