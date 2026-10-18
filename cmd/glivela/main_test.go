package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapCannotSelectDistribution(t *testing.T) {
	var cfg configuration
	decoder := json.NewDecoder(strings.NewReader(`{"mode":"node","xray":{"distribution":"/tmp/untrusted"}}`))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err == nil {
		t.Fatal("bootstrap overrode installed distribution")
	}
}

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
