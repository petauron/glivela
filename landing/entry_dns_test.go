package landing

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEntryDNSExceptions(t *testing.T) {
	p := EntryFirewall{UID: 1234, Revision: 1, DNS: []string{"100.100.100.100", "fd7a:115c:a1e0::53"}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	base := p
	base.DNS = nil
	before, after := base.objects(), p.objects()
	if len(after) != len(before)+4 {
		t.Fatal("not exactly two protocols per resolver")
	}
	// Only insert four exact destination/port returns after the existing reply
	// rule; every original isolation rule must remain byte-for-byte equivalent.
	if !reflect.DeepEqual(after[:5], before[:5]) || !reflect.DeepEqual(after[9:], before[5:]) {
		t.Fatal("changed non-DNS rules")
	}
	for _, obj := range after[5:9] {
		b, _ := json.Marshal(obj)
		var decoded map[string]map[string]any
		if json.Unmarshal(b, &decoded) != nil {
			t.Fatal("invalid rule")
		}
		expr := decoded["rule"]["expr"].([]any)
		if len(expr) != 3 || expr[1].(map[string]any)["match"].(map[string]any)["right"] != float64(53) {
			t.Fatal("DNS exception not confined to 53")
		}
	}
	if a, _ := base.identity(); func() string { a, _ := p.identity(); return a }() != a {
		t.Fatal("DNS changes must not leave conflicting tables")
	}
}
