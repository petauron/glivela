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

func TestBootstrapCannotOverwriteManagedBusinessState(t *testing.T) {
	var cfg configuration
	decoder := json.NewDecoder(strings.NewReader(`{"mode":"controller","nodes":[]}`))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) == nil {
		t.Fatal("bootstrap retained a second source of node business state")
	}
}

func TestBusinessKeyIsControllerStorageSettingOnly(t *testing.T) {
	for _, mode := range []string{"controller", "node", "verifier"} {
		path := filepath.Join(t.TempDir(), "bootstrap.json")
		raw, err := json.Marshal(configuration{Mode: mode, BusinessKey: "/private/example/business.key"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := readConfiguration(path)
		if mode == "controller" {
			if err != nil || cfg.BusinessKey != "/private/example/business.key" {
				t.Fatal("controller storage key reference lost", err)
			}
		} else if err == nil {
			t.Fatal("node/verifier accepted controller business key")
		}
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
