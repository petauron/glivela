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

// Inspect the exact kernel socket and dedicated UID without bypassing the
// source allowlist or forking a diagnostic process every poll.
func verifyOwnedListener(address string, port uint16, uid uint32) error {
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Is4In6() {
		return errors.New("control: invalid Xray listener address")
	}
	path := "/proc/net/tcp"
	if ip.Is6() {
		path = "/proc/net/tcp6"
	}
	file, err := os.Open(path)
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
	if err != nil || want.Is4In6() || uid == 0 || port == 0 {
		return false
	}
	scanner := bufio.NewScanner(io.LimitReader(reader, 16<<20))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != "0A" || fields[7] != strconv.FormatUint(uint64(uid), 10) {
			continue
		}
		host, service, ok := strings.Cut(fields[1], ":")
		expectedLength := 8
		if want.Is6() {
			expectedLength = 32
		}
		if !ok || len(host) != expectedLength {
			continue
		}
		p, e := strconv.ParseUint(service, 16, 16)
		if e != nil || uint16(p) != port {
			continue
		}
		var raw [16]byte
		valid := true
		for i := 0; i < len(host); i += 8 {
			word, e := strconv.ParseUint(host[i:i+8], 16, 32)
			if e != nil {
				valid = false
				break
			}
			binary.NativeEndian.PutUint32(raw[i/2:i/2+4], uint32(word))
		}
		if !valid {
			continue
		}
		if want.Is4() && netip.AddrFrom4([4]byte(raw[:4])) == want || want.Is6() && netip.AddrFrom16(raw) == want {
			return true
		}
	}
	return false
}
