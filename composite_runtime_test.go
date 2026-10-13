package meridian

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This opt-in CI gate checks the exact generated artifact with a pinned
// official image, without building or maintaining a fork. It is configuration
// acceptance only, not proof of traffic reachability or production deployment.
func TestCompositeOfficialCoreConfiguration(t *testing.T) {
	image := os.Getenv("GLIVELA_XRAY_IMAGE")
	if image == "" {
		t.Skip("official-core configuration gate requires GLIVELA_XRAY_IMAGE")
	}
	if !strings.HasPrefix(image, "ghcr.io/xtls/xray-core:") || !strings.Contains(image, "@sha256:") {
		t.Fatal("an immutable official Xray image is required")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plan := compositePlanFixture()
	plan.RealityEndpoints[0].PrivateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
	artifact, err := BuildDesiredArtifact(plan)
	if err != nil || artifact.Validate() != nil {
		t.Fatal("invalid generated composite artifact")
	}
	filename := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(filename, artifact.Config, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Official image entrypoint is Xray. No port, Docker socket, writable
	// host directory, or external network is available to the validator.
	err = exec.CommandContext(ctx, "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user", strconv.Itoa(os.Geteuid()),
		"--mount", "type=bind,src="+filename+",dst=/etc/xray/config.json,readonly", image,
		"run", "-test", "-c", "/etc/xray/config.json").Run()
	if err != nil {
		// Do not print configuration, generated private keys, or raw core logs.
		t.Fatalf("official Xray rejected generated composite configuration: %v", err)
	}
}
