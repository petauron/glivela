package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// The landing listener is IPv4 on both supported Linux architectures. Inspect
// its kernel socket and dedicated UID without bypassing the source allowlist
// with a local SOCKS connection, or forking a diagnostic process every poll.
func verifyOwnedListener(address string, port uint16, uid uint32) error {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return errors.New("control: cannot inspect Xray listener")
	}
	defer file.Close()
	if !ownedTCPListener(file, address, port, uid) {
		return errors.New("control: owned Xray listener is not ready")
	}
	return nil
}

func ownedTCPListener(reader io.Reader, address string, port uint16, uid uint32) bool {
	want, err := netip.ParseAddr(address)
	if err != nil || !want.Is4() || uid == 0 || port == 0 {
		return false
	}
	scanner := bufio.NewScanner(io.LimitReader(reader, 16<<20))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != "0A" || fields[7] != strconv.FormatUint(uint64(uid), 10) {
			continue
		}
		host, service, ok := strings.Cut(fields[1], ":")
		if !ok || len(host) != 8 {
			continue
		}
		p, e := strconv.ParseUint(service, 16, 16)
		if e != nil || uint16(p) != port {
			continue
		}
		word, e := strconv.ParseUint(host, 16, 32)
		if e != nil {
			continue
		}
		var raw [4]byte
		binary.NativeEndian.PutUint32(raw[:], uint32(word))
		if netip.AddrFrom4(raw) == want {
			return true
		}
	}
	return false
}
