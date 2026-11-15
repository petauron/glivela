package glivela

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDetachedLedgerAuthenticatesArchiveAndRetainsHistory(t *testing.T) {
	m := importFixture(t)
	key := bytes.Repeat([]byte{42}, 32)
	sealed, err := SealImportMaterial(m, key, "snapshot-a")
	if err != nil {
		t.Fatal(err)
	}
	archive, err := OpenImportMaterial(sealed, key, "snapshot-a")
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	ledger, err := SealImportLedger(archive, key, "snapshot-a", hash)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenImportLedger(ledger, key, "snapshot-a", hash, archive)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(m)
	b, _ := json.Marshal(got)
	if !bytes.Equal(a, b) {
		t.Fatal("history or business data changed")
	}
	if _, err = OpenImportLedger(ledger, key, "snapshot-a", strings.Repeat("b", 64), archive); err == nil {
		t.Fatal("different archive accepted")
	}
	archive.RetainedSource = bytes.Clone(archive.RetainedSource)
	archive.RetainedSource = bytes.Replace(archive.RetainedSource, []byte(`"sourceSchema":113`), []byte(`"sourceSchema":999`), 1)
	if archive.Validate() == nil {
		t.Fatal("edited source reused validated identity")
	}
}
