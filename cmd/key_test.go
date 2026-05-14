package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSopsConfRequiresExistingFile(t *testing.T) {
	t.Parallel()

	flakeDir := t.TempDir()
	cfg := &Config{
		FlakeDir: flakeDir,
		SopsConf: filepath.Join(flakeDir, ".sops.yaml"),
	}

	if err := ensureSopsConf(cfg); err == nil {
		t.Fatal("expected ensureSopsConf to fail when .sops.yaml is missing")
	}
}

func TestEnsureSopsConfRequiresAdminRecipients(t *testing.T) {
	t.Parallel()

	flakeDir := t.TempDir()
	confPath := filepath.Join(flakeDir, ".sops.yaml")
	raw := []byte(`creation_rules:
  - path_regex: vars/secrets/[^/]+\.yaml$
    key_groups:
      - age:
          - age1test
  - path_regex: vars/secrets/shared/[^/]+\.yaml$
    key_groups:
      - age:
          - age1test
  - path_regex: vars/admin/.+$
    key_groups:
      - age:
          - age1test
`)
	if err := os.WriteFile(confPath, raw, 0o644); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}

	cfg := &Config{
		FlakeDir: flakeDir,
		SopsConf: confPath,
	}

	if err := ensureSopsConf(cfg); err == nil {
		t.Fatal("expected ensureSopsConf to fail without admin PGP recipients")
	}
}
