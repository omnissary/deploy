package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

func seedSecrets(t *testing.T, path string, values map[string]string) {
	t.Helper()
	if err := sops.Edit(path, func(f *sops.File) error {
		for k, v := range values {
			f.Set(k, v)
		}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func readSecret(t *testing.T, path, key string) string {
	t.Helper()
	v, err := getSecret(path, key)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return v
}

// A ZFS root key already exists. During a later `machine deploy` the first
// decryption attempt fails transiently. The existing key must never be
// replaced with a freshly generated one.
func TestEnsureZFSPoolKeysKeepsExistingKeyOnTransientDecryptFailure(t *testing.T) {
	const machine = "m"
	cfg, armFailures := setupFlakyAgeFlake(t, machine)
	path := vars.MachineSecretsPath(cfg.FlakeDir, machine)

	const original = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	seedSecrets(t, path, map[string]string{"tank-root-key": original})
	seedSecrets(t, path, map[string]string{"other": "unrelated"})

	armFailures(1)
	_ = ensureZFSPoolKeys(path, machine, []string{"tank"})

	if got := readSecret(t, path, "tank-root-key"); got != original {
		t.Fatalf("existing ZFS root key was replaced:\n got  %s\n want %s", got, original)
	}
}

func TestEnsureZFSPoolKeysReportsDecryptFailureWithoutWriting(t *testing.T) {
	const machine = "m"
	cfg, armFailures := setupFlakyAgeFlake(t, machine)
	path := vars.MachineSecretsPath(cfg.FlakeDir, machine)
	seedSecrets(t, path, map[string]string{"tank-root-key": "original"})
	before := fileBytes(t, path)

	armFailures(1000)
	if err := ensureZFSPoolKeys(path, machine, []string{"tank", "new"}); err == nil {
		t.Fatal("expected an error when the secrets file cannot be decrypted")
	}
	if fileBytes(t, path) != before {
		t.Fatal("secrets file was modified despite decryption failure")
	}
}

func TestEnsureZFSPoolKeysCreatesOnlyMissingKeys(t *testing.T) {
	const machine = "m"
	cfg, _ := setupFlakyAgeFlake(t, machine)
	path := vars.MachineSecretsPath(cfg.FlakeDir, machine)
	seedSecrets(t, path, map[string]string{"tank-root-key": "original", "other": "x"})

	if err := ensureZFSPoolKeys(path, machine, []string{"tank", "data", "backup"}); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if got := readSecret(t, path, "tank-root-key"); got != "original" {
		t.Fatalf("existing key replaced: %q", got)
	}
	if got := readSecret(t, path, "other"); got != "x" {
		t.Fatalf("unrelated key changed: %q", got)
	}
	data := readSecret(t, path, "data-root-key")
	backup := readSecret(t, path, "backup-root-key")
	hexKey := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !hexKey.MatchString(data) || !hexKey.MatchString(backup) {
		t.Fatalf("generated keys are not 32-byte hex: %q %q", data, backup)
	}
	if data == backup {
		t.Fatal("pools received the same key")
	}
}

func TestEnsureZFSPoolKeysIsIdempotent(t *testing.T) {
	const machine = "m"
	cfg, _ := setupFlakyAgeFlake(t, machine)
	path := vars.MachineSecretsPath(cfg.FlakeDir, machine)

	if err := ensureZFSPoolKeys(path, machine, []string{"tank"}); err != nil {
		t.Fatal(err)
	}
	before := fileBytes(t, path)
	if err := ensureZFSPoolKeys(path, machine, []string{"tank"}); err != nil {
		t.Fatal(err)
	}
	if fileBytes(t, path) != before {
		t.Fatal("second run rewrote the secrets file")
	}
}

func TestEnsureZFSPoolKeysWithoutPoolsDoesNotDecrypt(t *testing.T) {
	const machine = "m"
	cfg, armFailures := setupFlakyAgeFlake(t, machine)
	path := vars.MachineSecretsPath(cfg.FlakeDir, machine)
	before := fileBytes(t, path)

	armFailures(1000)
	if err := ensureZFSPoolKeys(path, machine, nil); err != nil {
		t.Fatalf("expected no decryption without pools, got %v", err)
	}
	if fileBytes(t, path) != before {
		t.Fatal("file modified")
	}
}
