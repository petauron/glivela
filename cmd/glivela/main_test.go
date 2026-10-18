package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapFailsClosed(t *testing.T) {
	for _, body := range []string{`{}`, `{"mode":"arbitrary"}`, `{"mode":"node","unknown":true}`, `{"mode":"node"} {}`} {
		path := filepath.Join(t.TempDir(), "bootstrap.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if run(context.Background(), path) == nil {
			t.Fatal("invalid bootstrap accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "public.json")
	if err := os.WriteFile(path, []byte(`{"mode":"node"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if run(context.Background(), path) == nil {
		t.Fatal("public bootstrap accepted")
	}
}
