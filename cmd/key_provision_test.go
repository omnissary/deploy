package cmd

import (
	"os"
	"strings"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
	"git.tatikoma.dev/corpix/deploy/internal/sshkey"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func machineAge(t *testing.T, cfg *Config, machine string) string {
	t.Helper()
	age, err := sshkey.ToAge(mustRead(t, vars.MachineHostKeyPubPath(cfg.FlakeDir, machine)))
	if err != nil {
		t.Fatal(err)
	}
	return age
}

// useMachineIdentity switches decryption to the machine's own SSH host key,
// which is what sops-nix uses on the deployed machine.
func useMachineIdentity(t *testing.T, cfg *Config, machine string) {
	t.Helper()
	priv, err := sops.ReadFile(vars.MachineHostKeyPath(cfg.FlakeDir, machine))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := t.TempDir() + "/ssh_host_ed25519_key"
	if err := os.WriteFile(keyFile, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	sopstest.UseIdentities(t)
	t.Setenv("SOPS_AGE_SSH_PRIVATE_KEY_FILE", keyFile)
}

func TestEnsureHostKeyGeneratesConsistentPair(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"

	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatalf("ensureHostKey: %v", err)
	}
	priv, err := sops.ReadFile(vars.MachineHostKeyPath(af.cfg.FlakeDir, m))
	if err != nil {
		t.Fatal(err)
	}
	if err := sshkey.VerifyPair(priv, mustRead(t, vars.MachineHostKeyPubPath(af.cfg.FlakeDir, m))); err != nil {
		t.Fatal(err)
	}
	if conf := string(mustRead(t, af.cfg.SopsConf)); !strings.Contains(conf, machineAge(t, af.cfg, m)) {
		t.Fatal("machine age key missing from .sops.yaml")
	}
}

func TestEnsureHostKeyIsIdempotent(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"
	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	priv := mustRead(t, vars.MachineHostKeyPath(af.cfg.FlakeDir, m))
	conf := mustRead(t, af.cfg.SopsConf)

	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	if string(priv) != string(mustRead(t, vars.MachineHostKeyPath(af.cfg.FlakeDir, m))) {
		t.Fatal("private key rewritten")
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) {
		t.Fatal(".sops.yaml rewritten")
	}
}

// The deployed machine decrypts its secrets with its SSH host key. If the
// .pub goes missing, ensuring the host key (which every `secret set` does)
// must not mint a new key and re-key the machine's secrets away from the key
// the machine actually has.
func TestEnsureHostKeyWithMissingPublicKeyKeepsMachineIdentity(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"
	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	secrets := vars.MachineSecretsPath(af.cfg.FlakeDir, m)
	if err := createEncryptedYAMLIfMissing(af.cfg, secrets, "machine", m); err != nil {
		t.Fatal(err)
	}
	if err := setSecret(secrets, "rootfs", "precious"); err != nil {
		t.Fatal(err)
	}
	privPath := vars.MachineHostKeyPath(af.cfg.FlakeDir, m)
	pubPath := vars.MachineHostKeyPubPath(af.cfg.FlakeDir, m)
	privBefore := mustRead(t, privPath)
	pubBefore := mustRead(t, pubPath)
	if err := os.Remove(pubPath); err != nil {
		t.Fatal(err)
	}

	_ = ensureHostKey(af.cfg, m)

	if string(mustRead(t, privPath)) != string(privBefore) {
		t.Fatal("existing encrypted host private key was overwritten")
	}
	if pub, err := os.ReadFile(pubPath); err == nil && string(pub) != string(pubBefore) {
		t.Fatal("public key replaced by a different key")
	}
	useMachineIdentity(t, af.cfg, m)
	if v, err := getSecret(secrets, "rootfs"); err != nil || v != "precious" {
		t.Fatalf("machine can no longer read its secrets: %q, %v", v, err)
	}
}

func TestEnsureHostKeyWithMissingPrivateKeyFails(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"
	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	pubPath := vars.MachineHostKeyPubPath(af.cfg.FlakeDir, m)
	pubBefore := mustRead(t, pubPath)
	if err := os.Remove(vars.MachineHostKeyPath(af.cfg.FlakeDir, m)); err != nil {
		t.Fatal(err)
	}

	if err := ensureHostKey(af.cfg, m); err == nil {
		t.Fatal("expected an error for a public key without private key")
	}
	if string(mustRead(t, pubPath)) != string(pubBefore) {
		t.Fatal("public key changed")
	}
}

func TestEnsureHostKeyGrantsMachineAccessToPreexistingSecrets(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"
	secrets := vars.MachineSecretsPath(af.cfg.FlakeDir, m)
	if err := os.MkdirAll(vars.MachineHostKeyDir(af.cfg.FlakeDir, m), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := createEncryptedYAMLIfMissing(af.cfg, secrets, "machine", m); err != nil {
		t.Fatal(err)
	}
	if err := setSecret(secrets, "k", "v"); err != nil {
		t.Fatal(err)
	}

	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatalf("ensureHostKey: %v", err)
	}

	useMachineIdentity(t, af.cfg, m)
	if v, err := getSecret(secrets, "k"); err != nil || v != "v" {
		t.Fatalf("machine cannot read secrets created before its key: %q, %v", v, err)
	}
}

func TestEnsureHostKeyKeepsAdminAccess(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"
	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	secrets := vars.MachineSecretsPath(af.cfg.FlakeDir, m)
	if err := createEncryptedYAMLIfMissing(af.cfg, secrets, "machine", m); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{secrets, vars.MachineHostKeyPath(af.cfg.FlakeDir, m)} {
		if err := sops.Verify(path); err != nil {
			t.Fatalf("session identity lost access to %s: %v", path, err)
		}
	}
}
