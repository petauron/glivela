//go:build linux

package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	glivela "github.com/petauron/glivela"
)

type entrySocket struct {
	network, address string
	port             uint16
}

func verifyEntryProcess(container EntryContainer, state entryContainerState, desired Desired) error {
	root := filepath.Join("/proc", strconv.Itoa(state.State.Pid))
	if err := verifyEntryConfigFile(filepath.Join(root, "root/etc/glivela/config.json"), desired.Config); err != nil {
		return err
	}
	return verifyEntryProcessResources(root, container.UID, container.GID, desired, container.GID != 0 && len(desired.Entry.HysteriaEndpoints) > 0)
}

func verifyEntryProcessResources(root string, uid, gid uint32, desired Desired, allowBind bool) error {
	status, err := os.Open(filepath.Join(root, "status"))
	if err != nil {
		return errors.New("control: cannot inspect owned entry process")
	}
	err = verifyEntryIdentity(status, uid, gid, allowBind)
	status.Close()
	if err != nil {
		return err
	}
	sockets := []entrySocket{{"tcp", "127.0.0.1", glivela.XrayAPIListenPort}}
	for _, endpoint := range desired.Entry.RealityEndpoints {
		sockets = append(sockets, entrySocket{"tcp", endpoint.ListenAddress, uint16(endpoint.ListenPort)})
	}
	for _, endpoint := range desired.Entry.HysteriaEndpoints {
		sockets = append(sockets, entrySocket{"udp", "0.0.0.0", uint16(endpoint.ListenPort)})
	}
	needed := map[string][]entrySocket{}
	for _, socket := range sockets {
		needed[socket.network] = append(needed[socket.network], socket)
	}
	inodes := map[string]bool{}
	for network, wanted := range needed {
		file, err := os.Open(filepath.Join(root, "net", network))
		if err != nil {
			return errors.New("control: entry socket table unavailable")
		}
		found, err := entrySocketInodes(file, wanted, uid)
		file.Close()
		if err != nil {
			return err
		}
		for _, inode := range found {
			inodes[inode] = true
		}
	}
	// The namespace's listener table alone is not ownership proof (host mode
	// shares it). Each required socket must be an FD of this exact process.
	files, err := os.Open(filepath.Join(root, "fd"))
	if err != nil {
		return errors.New("control: entry process descriptors unavailable")
	}
	defer files.Close()
	count := 0
	for len(inodes) > 0 {
		names, err := files.Readdirnames(128)
		for _, name := range names {
			count++
			if count > 65536 {
				return errors.New("control: entry descriptor inspection exceeds limit")
			}
			value, err := os.Readlink(filepath.Join(root, "fd", name))
			if err == nil && strings.HasPrefix(value, "socket:[") && strings.HasSuffix(value, "]") {
				delete(inodes, strings.TrimSuffix(strings.TrimPrefix(value, "socket:["), "]"))
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("control: entry descriptors changed during inspection")
		}
	}
	if len(inodes) != 0 {
		return errors.New("control: entry listeners belong to another process")
	}
	return nil
}

func verifyEntryProcessStatus(reader io.Reader, container EntryContainer, hy2 bool) error {
	return verifyEntryIdentity(reader, container.UID, container.GID, hy2)
}

func verifyEntryIdentity(reader io.Reader, uid, gid uint32, hy2 bool) error {
	wanted := map[string]bool{"Uid:": false, "Gid:": false, "NoNewPrivs:": false, "CapEff:": false, "CapPrm:": false, "CapBnd:": false}
	limited := &io.LimitedReader{R: reader, N: (64 << 10) + 1}
	scanner := bufio.NewScanner(limited)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		seen, needed := wanted[fields[0]]
		if !needed {
			continue
		}
		if seen {
			return errors.New("control: ambiguous entry process identity")
		}
		wanted[fields[0]] = true
		switch fields[0] {
		case "Uid:", "Gid:":
			if len(fields) != 5 {
				return errors.New("control: invalid entry process identity")
			}
			for _, value := range fields[1:] {
				id, err := strconv.ParseUint(value, 10, 32)
				if err != nil || fields[0] == "Uid:" && uint32(id) != uid || fields[0] == "Gid:" && gid != 0 && uint32(id) != gid {
					return errors.New("control: entry process user/group changed")
				}
			}
		case "NoNewPrivs:":
			if len(fields) != 2 || fields[1] != "1" {
				return errors.New("control: entry process privilege escalation is not disabled")
			}
		default:
			caps, err := strconv.ParseUint(fields[1], 16, 64)
			var allowed uint64
			if gid != 0 && hy2 {
				allowed = 1 << 10
			} // CAP_NET_BIND_SERVICE only.
			if len(fields) != 2 || err != nil || caps & ^allowed != 0 {
				return errors.New("control: entry process capabilities changed")
			}
		}
	}
	if scanner.Err() != nil || limited.N == 0 {
		return errors.New("control: cannot read entry process identity")
	}
	for _, seen := range wanted {
		if !seen {
			return errors.New("control: entry process identity incomplete")
		}
	}
	return nil
}

func entrySocketInodes(reader io.Reader, wanted []entrySocket, uid uint32) (map[entrySocket]string, error) {
	found := map[entrySocket]string{}
	limited := &io.LimitedReader{R: reader, N: (16 << 20) + 1}
	scanner := bufio.NewScanner(limited)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[7] != strconv.FormatUint(uint64(uid), 10) {
			continue
		}
		host, service, ok := strings.Cut(fields[1], ":")
		if !ok || len(host) != 8 {
			continue
		}
		word, err := strconv.ParseUint(host, 16, 32)
		if err != nil {
			continue
		}
		port, err := strconv.ParseUint(service, 16, 16)
		if err != nil {
			continue
		}
		var raw [4]byte
		binary.NativeEndian.PutUint32(raw[:], uint32(word))
		for _, socket := range wanted {
			state := "0A"
			if socket.network == "udp" {
				state = "07"
			}
			if socket.address != netip.AddrFrom4(raw).String() || socket.port != uint16(port) || fields[3] != state {
				continue
			}
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil || inode == 0 || found[socket] != "" && found[socket] != fields[9] {
				return nil, errors.New("control: ambiguous entry listener ownership")
			}
			found[socket] = fields[9]
		}
	}
	if scanner.Err() != nil || limited.N == 0 || len(found) != len(wanted) {
		return nil, errors.New("control: owned entry listeners are not ready")
	}
	return found, nil
}
