//go:build linux

package control

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

// A loopback connect alone cannot prove that our child owns the listener.
func verifyReadinessListener(pid, port int) error {
	root := filepath.Join("/proc", strconv.Itoa(pid))
	file, err := os.Open(filepath.Join(root, "net", "tcp"))
	if err != nil {
		return err
	}
	found, err := entrySocketInodes(file, []entrySocket{{"tcp", "127.0.0.1", uint16(port)}}, uint32(os.Geteuid()))
	file.Close()
	if err != nil {
		return err
	}
	inode := found[entrySocket{"tcp", "127.0.0.1", uint16(port)}]
	descriptors, err := os.ReadDir(filepath.Join(root, "fd"))
	if err != nil {
		return err
	}
	if len(descriptors) > 65536 {
		return errors.New("control: readiness descriptors exceed limit")
	}
	for _, descriptor := range descriptors {
		link, err := os.Readlink(filepath.Join(root, "fd", descriptor.Name()))
		if err == nil && link == "socket:["+inode+"]" {
			return nil
		}
	}
	return errors.New("control: readiness listener is not owned by the probe process")
}
