//go:build linux

package control

import (
	"net"
	"os"
	"testing"
)

func TestEntryReadinessListenerOwnership(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if err := verifyReadinessListener(os.Getpid(), port); err != nil {
		t.Fatal(err)
	}
	if err := verifyReadinessListener(os.Getppid(), port); err == nil {
		t.Fatal("another process accepted as probe owner")
	}
}
