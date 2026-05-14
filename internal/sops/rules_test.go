package sops

import (
	"os"
	"path/filepath"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

const testAdminPGP = "0123456789ABCDEF0123456789ABCDEF01234567"

func TestInitConfRequiresAdminPGP(t *testing.T) {
	t.Parallel()

	confPath := filepath.Join(t.TempDir(), ".sops.yaml")
	if err := InitConf(confPath, nil); err == nil {
		t.Fatal("expected InitConf to require an admin PGP recipient")
	}
}

func TestRequireAdminPGPConfigRejectsMissingRecipients(t *testing.T) {
	t.Parallel()

	confPath := filepath.Join(t.TempDir(), ".sops.yaml")
	raw := []byte(`creation_rules:
  - path_regex: vars/secrets/[^/]+\.yaml$
    key_groups:
      - age:
          - age1test
  - path_regex: vars/secrets/shared/[^/]+\.yaml$
    key_groups:
      - pgp:
          - ` + testAdminPGP + `
  - path_regex: vars/admin/.+$
    key_groups:
      - pgp:
          - ` + testAdminPGP + `
`)
	if err := os.WriteFile(confPath, raw, 0o644); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}

	if err := RequireAdminPGPConfig(confPath); err == nil {
		t.Fatal("expected RequireAdminPGPConfig to reject missing generic admin PGP recipients")
	}
}

func TestAddSessionKeySkipsAdminRule(t *testing.T) {
	t.Parallel()

	flakeDir := t.TempDir()
	confPath := filepath.Join(flakeDir, ".sops.yaml")
	if err := InitConf(confPath, []string{testAdminPGP}); err != nil {
		t.Fatalf("InitConf: %v", err)
	}

	changed, err := AddSessionKey(confPath, flakeDir, "age1session", func(string, string) error { return nil })
	if err != nil {
		t.Fatalf("AddSessionKey: %v", err)
	}
	if !changed {
		t.Fatal("expected AddSessionKey to change the config")
	}

	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		t.Fatalf("loadSopsYAML: %v", err)
	}

	for _, rule := range cfg.CreationRules {
		if len(rule.KeyGroups) == 0 {
			continue
		}
		group := rule.KeyGroups[0]
		switch rule.PathRegex {
		case vars.AdminVarsRegex:
			if containsStr(group.Age, "age1session") {
				t.Fatal("session recipient must not be added to vars/admin rules")
			}
		case vars.GenericMachineRegex, vars.GenericSharedRegex:
			if !containsStr(group.Age, "age1session") {
				t.Fatalf("expected session recipient on %q", rule.PathRegex)
			}
		}
	}
}

func TestRemoveAdminKeyRejectsLastRecipient(t *testing.T) {
	t.Parallel()

	flakeDir := t.TempDir()
	confPath := filepath.Join(flakeDir, ".sops.yaml")
	if err := InitConf(confPath, []string{testAdminPGP}); err != nil {
		t.Fatalf("InitConf: %v", err)
	}

	if _, err := RemoveAdminKey(confPath, flakeDir, testAdminPGP, func(string, string) error { return nil }); err == nil {
		t.Fatal("expected RemoveAdminKey to reject removing the last admin PGP recipient")
	}
}
