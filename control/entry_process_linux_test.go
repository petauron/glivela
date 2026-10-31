//go:build linux

package control

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestEntryProcessStatusRequiresActualDedicatedIdentityAndCapabilities(t *testing.T) {
	c := EntryContainer{UID: 0, GID: 12346}
	status := "Uid:\t0\t0\t0\t0\nGid:\t12346\t12346\t12346\t12346\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapBnd:\t0000000000000000\n"
	if err := verifyEntryProcessStatus(strings.NewReader(status), c, false); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		strings.Replace(status, "Uid:\t0\t0\t0\t0", "Uid:\t1\t1\t1\t1", 1),
		strings.Replace(status, "Gid:\t12346\t12346\t12346\t12346", "Gid:\t0\t0\t0\t0", 1),
		strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1),
		strings.Replace(status, "CapEff:\t0000000000000000", "CapEff:\t00000000ffffffff", 1),
		strings.Replace(status, "CapBnd:\t0000000000000000", "CapBnd:\t0000000000000400", 1),
		strings.Replace(status, "NoNewPrivs:\t1\n", "", 1), status + "Uid:\t0\t0\t0\t0\n",
	} {
		if verifyEntryProcessStatus(strings.NewReader(data), c, false) == nil {
			t.Fatal("unowned or privileged actual process accepted")
		}
	}
	bind := strings.ReplaceAll(status, "0000000000000000", "0000000000000400")
	if err := verifyEntryProcessStatus(strings.NewReader(bind), c, true); err != nil {
		t.Fatal("authorized host HY2 bind capability rejected", err)
	}
	c.UID, c.GID = 65532, 0
	bridge := strings.Replace(status, "Uid:\t0\t0\t0\t0", "Uid:\t65532\t65532\t65532\t65532", 1)
	if err := verifyEntryProcessStatus(strings.NewReader(bridge), c, true); err != nil {
		t.Fatal("non-root bridge process rejected", err)
	}
	if verifyEntryProcessStatus(strings.NewReader(strings.ReplaceAll(bridge, "0000000000000000", "0000000000000400")), c, true) == nil {
		t.Fatal("bridge gained a host binding capability")
	}
}

func TestEntrySocketReadbackRequiresExactListenerAndInode(t *testing.T) {
	tcp := entrySocket{"tcp", "100.64.0.8", 10443}
	row := "0: 08004064:28CB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345\n"
	got, err := entrySocketInodes(strings.NewReader(row), []entrySocket{tcp}, 0)
	if err != nil || got[tcp] != "12345" {
		t.Fatal("exact root/GID-host listener not found", err)
	}
	for _, data := range []string{strings.Replace(row, " 0 0 12345", " 65532 0 12345", 1), strings.Replace(row, " 0A ", " 01 ", 1), strings.Replace(row, "08004064", "00000000", 1), strings.Replace(row, ":28CB", ":28CC", 1), strings.Replace(row, "12345", "0", 1), row + strings.Replace(row, "12345", "67890", 1)} {
		if _, err := entrySocketInodes(strings.NewReader(data), []entrySocket{tcp}, 0); err == nil {
			t.Fatal("wrong/ambiguous listening socket accepted")
		}
	}
	ipv6 := entrySocket{"tcp", "2606:4700:4700::1111", 10443}
	raw := netip.MustParseAddr(ipv6.address).As16()
	hexAddress := ""
	for offset := 0; offset < len(raw); offset += 4 {
		hexAddress += fmt.Sprintf("%08X", binary.NativeEndian.Uint32(raw[offset:offset+4]))
	}
	v6row := strings.Replace(row, "08004064", hexAddress, 1)
	if got, err := entrySocketInodes(strings.NewReader(v6row), []entrySocket{ipv6}, 0); err != nil || got[ipv6] != "12345" {
		t.Fatal("exact IPv6 listener was not recognized", err)
	}
	if _, err := entrySocketInodes(strings.NewReader(strings.Replace(v6row, hexAddress, strings.Repeat("0", 32), 1)), []entrySocket{ipv6}, 0); err == nil {
		t.Fatal("wildcard IPv6 listener accepted as exact binding")
	}
	udp := entrySocket{"udp", "0.0.0.0", 443}
	udpRow := "0: 00000000:01BB 00000000:0000 07 00000000:00000000 00:00000000 00000000 65532 0 54321\n"
	if got, err := entrySocketInodes(strings.NewReader(udpRow), []entrySocket{udp}, 65532); err != nil || got[udp] != "54321" {
		t.Fatal("explicit HY2 UDP listener rejected", err)
	}
}
