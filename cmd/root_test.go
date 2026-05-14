package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func writeFlake(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "flake.nix"), []byte(content), 0o644); err != nil {
		t.Fatalf("write flake.nix: %v", err)
	}
}

func requireNix(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nix"); err != nil {
		t.Skip("nix not in PATH")
	}
}

func TestRequireMachineRejectsMissingMachineConfig(t *testing.T) {
	t.Parallel()
	requireNix(t)

	flakeDir := t.TempDir()
	writeFlake(t, flakeDir, `{ outputs = _: { nixosConfigurations = {}; }; }`)

	cfg := &Config{FlakeDir: flakeDir}
	if _, err := requireMachine(cfg, "pegasus"); err == nil {
		t.Fatal("expected missing machine error")
	}
}

func TestRequireMachineAcceptsExistingMachineConfig(t *testing.T) {
	t.Parallel()
	requireNix(t)

	flakeDir := t.TempDir()
	writeFlake(t, flakeDir, `{ outputs = _: { nixosConfigurations = { pegasus = {}; }; }; }`)

	machine, err := requireMachine(&Config{FlakeDir: flakeDir}, "pegasus")
	if err != nil {
		t.Fatalf("requireMachine: %v", err)
	}
	if machine != "pegasus" {
		t.Fatalf("unexpected machine %q", machine)
	}
}
