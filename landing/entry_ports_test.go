package landing

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEntryFirewallKeepsExactPortsForSharedRelayAddress(t *testing.T) {
	p := EntryFirewall{UID: 1234, Revision: 1, Peers: []string{"2606:4700:4700::1111"}, PeerPorts: map[string]int{"2606:4700:4700::1111": 24008}, ExtraPeerPorts: map[string][]int{"2606:4700:4700::1111": {24002}}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p.objects())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "24008") || !strings.Contains(string(raw), "24002") || strings.Contains(string(raw), "1080") {
		t.Fatal("exact ports lost or expanded")
	}
	p.ExtraPeerPorts["2606:4700:4700::1111"] = []int{443}
	if p.validate() == nil {
		t.Fatal("accepted unissued port")
	}
}
