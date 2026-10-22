package control

import (
	"reflect"
	"testing"
)

func TestExistingEntryDNS(t *testing.T) {
	got, err := parseEntryDNS("# retained\nnameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\nnameserver 100.100.100.100 # duplicate\nsearch example.invalid\n")
	if err != nil || !reflect.DeepEqual(got, []string{"100.100.100.100", "fd7a:115c:a1e0::53"}) {
		t.Fatal("existing resolvers not preserved", got, err)
	}
	for _, raw := range []string{"", "nameserver hostname", "nameserver 0.0.0.0", "nameserver 224.0.0.1", "nameserver fe80::1%eth0", "nameserver 127.0.0.1 extra"} {
		if _, err := parseEntryDNS(raw); err == nil {
			t.Fatal("accepted invalid resolver", raw)
		}
	}
}
