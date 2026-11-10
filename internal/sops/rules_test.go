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

func TestParsePerGroupSharedRegex(t *testing.T) {
	t.Parallel()

	if _, ok := parsePerGroupSharedRegex(vars.GenericSharedRegex); ok {
		t.Fatal("generic shared rule must not be classified as per-group")
	}
	name, ok := parsePerGroupSharedRegex(vars.SharedSecretsRegex("loki-ca"))
	if !ok || name != "loki-ca" {
		t.Fatalf("expected per-group match for loki-ca, got (%q, %v)", name, ok)
	}
	if _, ok := parsePerGroupSharedRegex(vars.GenericMachineRegex); ok {
		t.Fatal("machine generic rule must not be classified as per-group shared")
	}
}

func TestInitConfCreatesFileAndRefusesToOverwrite(t *testing.T) {
	t.Parallel()

	confPath := filepath.Join(t.TempDir(), ".sops.yaml")
	if err := InitConf(confPath, []string{testAdminPGP}); err != nil {
		t.Fatalf("InitConf: %v", err)
	}
	if err := RequireAdminPGPConfig(confPath); err != nil {
		t.Fatalf("created config is invalid: %v", err)
	}
	before, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := InitConf(confPath, []string{"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"}); err == nil {
		t.Fatal("expected InitConf to refuse an existing file")
	}
	after, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing .sops.yaml was modified")
	}
}

func TestListAdminAndSessionKeysReadGenericRule(t *testing.T) {
	t.Parallel()

	confPath := filepath.Join(t.TempDir(), ".sops.yaml")
	rules, err := DesiredRules(Model{
		Admins:   []string{testAdminPGP},
		Sessions: []string{"age1session"},
		Machines: map[string]string{"m": "age1machine"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSopsYAML(confPath, sopsYAML{CreationRules: rules}); err != nil {
		t.Fatal(err)
	}

	admins, err := ListAdminKeys(confPath)
	if err != nil || len(admins) != 1 || admins[0] != testAdminPGP {
		t.Fatalf("ListAdminKeys = %v, %v", admins, err)
	}
	sessions, err := ListSessionKeys(confPath)
	if err != nil || len(sessions) != 1 || sessions[0] != "age1session" {
		t.Fatalf("ListSessionKeys = %v, %v", sessions, err)
	}
}

func TestListAdminKeysRequiresGenericRule(t *testing.T) {
	t.Parallel()

	confPath := filepath.Join(t.TempDir(), ".sops.yaml")
	if err := os.WriteFile(confPath, []byte("creation_rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ListAdminKeys(confPath); err == nil {
		t.Fatal("expected error without generic rule")
	}
	if _, err := ListSessionKeys(confPath); err == nil {
		t.Fatal("expected error without generic rule")
	}
}

func TestEncryptedInventoryIncludesNestedAdminState(t *testing.T) {
	dir := t.TempDir()
	folder := filepath.Join(dir, "vars", "admin", "pki")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(folder, "root.yaml")
	os.WriteFile(secret, []byte("fixture"), 0o600)
	os.WriteFile(secret+".pub", []byte("public"), 0o644)
	files, err := ListEncryptedFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != secret {
		t.Fatalf("nested admin inventory: %v", files)
	}
}
