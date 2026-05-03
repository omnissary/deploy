package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequireMachineRejectsMissingMachineConfig(t *testing.T) {
	t.Parallel()

	flakeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.nix"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write flake.nix: %v", err)
	}

	cfg := &Config{FlakeDir: flakeDir}
	if _, err := requireMachine(cfg, "pegasus"); err == nil {
		t.Fatal("expected missing machine config error")
	}
}

func TestRequireMachineAcceptsExistingMachineConfig(t *testing.T) {
	t.Parallel()

	flakeDir := t.TempDir()
	machineDir := filepath.Join(flakeDir, "machines", "pegasus")
	if err := os.MkdirAll(machineDir, 0o755); err != nil {
		t.Fatalf("create machine dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(flakeDir, "flake.nix"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write flake.nix: %v", err)
	}
	if err := os.WriteFile(filepath.Join(machineDir, "default.nix"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write machine config: %v", err)
	}

	machine, err := requireMachine(&Config{FlakeDir: flakeDir}, "pegasus")
	if err != nil {
		t.Fatalf("requireMachine: %v", err)
	}
	if machine != "pegasus" {
		t.Fatalf("unexpected machine %q", machine)
	}
}
