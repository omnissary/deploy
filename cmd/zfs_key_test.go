package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/agekey"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func unsetenv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	os.Unsetenv(key)
}

// setupFlakyAgeFlake creates a flake with an age-encrypted machine secrets
// file. The age identity is served by SOPS_AGE_KEY_CMD, which fails on its
// first `failures` invocations and succeeds afterwards, the way a missed
// YubiKey touch or a cancelled pinentry does.
func setupFlakyAgeFlake(t *testing.T, machine string) (cfg *Config, armFailures func(n int)) {
	t.Helper()

	pair, err := agekey.Generate()
	if err != nil {
		t.Fatalf("generate age key: %v", err)
	}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "age.key")
	counter := filepath.Join(dir, "failures-left")
	script := filepath.Join(dir, "age-key-cmd.sh")
	if err := os.WriteFile(keyFile, []byte(pair.Private+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(counter, []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte(fmt.Sprintf(`#!/bin/sh
n=$(cat %[1]q)
if [ "$n" -gt 0 ]; then
  echo $((n - 1)) > %[1]q
  echo "touch timeout" >&2
  exit 1
fi
cat %[2]q
`, counter, keyFile)), 0o700); err != nil {
		t.Fatal(err)
	}

	unsetenv(t, "SOPS_AGE_KEY")
	unsetenv(t, "SOPS_AGE_KEY_FILE")
	unsetenv(t, "SOPS_AGE_SSH_PRIVATE_KEY_FILE")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	t.Setenv("SOPS_AGE_KEY_CMD", script)

	flakeDir := filepath.Join(dir, "flake")
	cfg = &Config{FlakeDir: flakeDir, SopsConf: filepath.Join(flakeDir, ".sops.yaml")}
	if err := os.MkdirAll(flakeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf("creation_rules:\n  - path_regex: vars/secrets/[^/]+\\.yaml$\n    key_groups:\n      - age:\n          - %s\n", pair.Public)
	if err := os.WriteFile(cfg.SopsConf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := createEncryptedYAMLIfMissing(cfg, vars.MachineSecretsPath(flakeDir, machine), "machine", machine); err != nil {
		t.Fatalf("create secrets file: %v", err)
	}

	return cfg, func(n int) {
		if err := os.WriteFile(counter, []byte(fmt.Sprint(n)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A ZFS root key already exists. During a later `machine deploy` the first
// decryption attempt fails transiently. ensureZFSPoolKey must not treat that as
// "key missing" and replace the existing key with a freshly generated one.
func TestEnsureZFSPoolKeyKeepsExistingKeyOnTransientDecryptFailure(t *testing.T) {
	const machine, pool = "m", "tank"
	cfg, armFailures := setupFlakyAgeFlake(t, machine)
	path := vars.MachineSecretsPath(cfg.FlakeDir, machine)

	const original = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := sops.SetYAML(path, pool+"-root-key", original); err != nil {
		t.Fatalf("seed root key: %v", err)
	}
	if err := sops.SetYAML(path, "other", "unrelated"); err != nil {
		t.Fatalf("add second secret: %v", err)
	}

	armFailures(1)
	_ = ensureZFSPoolKey(cfg, machine, pool)

	got, err := sops.DecryptYAMLExtract(path, pool+"-root-key")
	if err != nil {
		t.Fatalf("read back root key: %v", err)
	}
	if got != original {
		t.Fatalf("existing ZFS root key was replaced:\n got  %s\n want %s", got, original)
	}
}

// Same as above but with the decryption failing persistently: nothing should
// be written, and the caller must get an error rather than a silent no-op.
func TestEnsureZFSPoolKeyReportsPersistentDecryptFailure(t *testing.T) {
	const machine, pool = "m", "tank"
	cfg, armFailures := setupFlakyAgeFlake(t, machine)
	path := vars.MachineSecretsPath(cfg.FlakeDir, machine)

	if err := sops.SetYAML(path, pool+"-root-key", "original"); err != nil {
		t.Fatalf("seed root key: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	armFailures(1000)
	if err := ensureZFSPoolKey(cfg, machine, pool); err == nil {
		t.Fatal("expected an error when the secrets file cannot be decrypted")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("secrets file was modified despite decryption failure")
	}
}
