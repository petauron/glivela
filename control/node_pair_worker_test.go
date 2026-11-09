package control

import "testing"

func TestPairingDirectoriesRequireExactInstalledDeclarations(t *testing.T) {
	unit := "[Service]\nStateDirectory=app-node\nStateDirectory=app-pair\nStateDirectory=app-companion\n"
	paths := []string{"/var/lib/app-node", "/var/lib/app-pair", "/var/lib/app-companion"}
	if err := pairingDeclaredDirectories(unit, paths); err != nil {
		t.Fatal(err)
	}
	if err := pairingDeclaredDirectories(unit, []string{"/var/lib/another-application"}); err == nil {
		t.Fatal("foreign private directory accepted")
	}
	if err := pairingDeclaredDirectories(unit, []string{"/var/lib/app-node/../app-pair"}); err == nil {
		t.Fatal("unclean alias accepted")
	}
	if err := pairingDeclaredDirectories(unit+"StateDirectory=../foreign\n", paths); err == nil {
		t.Fatal("escaping declaration accepted")
	}
}
