package control

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Preserve the resolver actually configured for the worker. No remote desired
// message can add destinations, and this does not change the host DNS or unit.
func (d *NativeEntryDriver) existingEntryDNS() ([]string, error) {
	path := "/etc/resolv.conf"
	unit, err := d.installationNames()
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(unit + ".d/90-preserve-dns.conf"); err == nil {
		// The caller verifies the exact override and effective mount separately.
		path = filepath.Join(filepath.Dir(d.Installation), d.Service, "reality-resolv.conf")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// Distribution resolv.conf commonly points into /run. Validate the resolved
	// regular file and every parent with the existing root-owned-file checks.
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	raw, err := readRootDNSFile(path)
	if err != nil {
		return nil, err
	}
	return parseEntryDNS(string(raw))
}

func parseEntryDNS(raw string) ([]string, error) {
	var result []string
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(strings.SplitN(strings.SplitN(line, "#", 2)[0], ";", 2)[0])
		if len(fields) == 0 || fields[0] != "nameserver" {
			continue
		}
		if len(fields) != 2 {
			return nil, errors.New("control: invalid existing DNS configuration")
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("control: invalid existing DNS address")
		}
		address := ip.Unmap().String()
		if !seen[address] {
			result = append(result, address)
			seen[address] = true
		}
	}
	if len(result) == 0 || len(result) > 16 {
		return nil, errors.New("control: existing DNS inventory missing or too large")
	}
	return result, nil
}
