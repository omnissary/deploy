package nix

import (
	"os"
	"strings"
	"testing"
)

func TestCommandEnvIncludesNixConfig(t *testing.T) {
	t.Parallel()

	oldCores := buildCores
	oldJobs := maxJobs
	t.Cleanup(func() {
		buildCores = oldCores
		maxJobs = oldJobs
	})

	SetConfig("12", "1")
	env := commandEnv()

	var nixConfig string
	for _, item := range env {
		if strings.HasPrefix(item, "NIX_CONFIG=") {
			nixConfig = strings.TrimPrefix(item, "NIX_CONFIG=")
			break
		}
	}

	if nixConfig == "" {
		t.Fatal("missing NIX_CONFIG in environment")
	}
	if !strings.Contains(nixConfig, "cores = 12") {
		t.Fatalf("missing cores config in %q", nixConfig)
	}
	if !strings.Contains(nixConfig, "max-jobs = 1") {
		t.Fatalf("missing max-jobs config in %q", nixConfig)
	}
}

func TestCommandEnvWithoutConfigUsesBaseEnvironment(t *testing.T) {
	t.Parallel()

	oldCores := buildCores
	oldJobs := maxJobs
	t.Cleanup(func() {
		buildCores = oldCores
		maxJobs = oldJobs
	})

	SetConfig("", "")
	env := commandEnv()

	for _, item := range env {
		if strings.HasPrefix(item, "NIX_CONFIG=") {
			t.Fatalf("unexpected NIX_CONFIG in environment: %q", item)
		}
	}

	if len(env) != len(os.Environ()) {
		t.Fatalf("unexpected environment length: got %d want %d", len(env), len(os.Environ()))
	}
}
