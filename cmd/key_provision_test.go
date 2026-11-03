package cmd

import (
	"bytes"
	"os"
	"os/exec"
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

// useMachineIdentity switches decryption to the machine's SSH host key
// converted with ssh-to-age, which is what sops-nix does on the machine.
func useMachineIdentity(t *testing.T, cfg *Config, machine string) {
	t.Helper()
	priv, err := sops.ReadFile(vars.MachineHostKeyPath(cfg.FlakeDir, machine))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh-to-age", "-private-key")
	cmd.Stdin = bytes.NewReader(priv)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ssh-to-age -private-key: %v", err)
	}
	sopstest.UseIdentities(t, sopstest.Identity{Private: strings.TrimSpace(string(out)), Public: machineAge(t, cfg, machine)})
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

func TestEnsureInitrdKeyGeneratesCommentedPair(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"
	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}

	if err := ensureInitrdKey(af.cfg, m); err != nil {
		t.Fatalf("ensureInitrdKey: %v", err)
	}
	pub := mustRead(t, vars.MachineInitrdKeyPubPath(af.cfg.FlakeDir, m))
	if !strings.HasSuffix(string(pub), " root@m-initrd\n") {
		t.Fatalf("public key line %q lacks initrd comment", pub)
	}
	priv, err := sops.ReadFile(vars.MachineInitrdKeyPath(af.cfg.FlakeDir, m))
	if err != nil {
		t.Fatal(err)
	}
	if err := sshkey.VerifyPair(priv, pub); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureInitrdKeyIsIdempotent(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"
	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	if err := ensureInitrdKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	priv := mustRead(t, vars.MachineInitrdKeyPath(af.cfg.FlakeDir, m))
	pub := mustRead(t, vars.MachineInitrdKeyPubPath(af.cfg.FlakeDir, m))

	if err := ensureInitrdKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	if string(priv) != string(mustRead(t, vars.MachineInitrdKeyPath(af.cfg.FlakeDir, m))) ||
		string(pub) != string(mustRead(t, vars.MachineInitrdKeyPubPath(af.cfg.FlakeDir, m))) {
		t.Fatal("initrd key rewritten")
	}
}

func TestEnsureInitrdKeyRestoresMissingPublicKey(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"
	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	if err := ensureInitrdKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	privPath := vars.MachineInitrdKeyPath(af.cfg.FlakeDir, m)
	pubPath := vars.MachineInitrdKeyPubPath(af.cfg.FlakeDir, m)
	priv, pub := mustRead(t, privPath), mustRead(t, pubPath)
	if err := os.Remove(pubPath); err != nil {
		t.Fatal(err)
	}

	if err := ensureInitrdKey(af.cfg, m); err != nil {
		t.Fatalf("ensureInitrdKey: %v", err)
	}
	if string(mustRead(t, privPath)) != string(priv) {
		t.Fatal("private key changed")
	}
	if string(mustRead(t, pubPath)) != string(pub) {
		t.Fatalf("restored %q, want %q", mustRead(t, pubPath), pub)
	}
}

func TestEnsureInitrdKeyWithMissingPrivateKeyFails(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"
	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	if err := ensureInitrdKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(vars.MachineInitrdKeyPath(af.cfg.FlakeDir, m)); err != nil {
		t.Fatal(err)
	}
	if err := ensureInitrdKey(af.cfg, m); err == nil {
		t.Fatal("expected error")
	}
	if fileExists(vars.MachineInitrdKeyPath(af.cfg.FlakeDir, m)) {
		t.Fatal("a new private key was generated")
	}
}

func TestEnsureInitrdKeyWithoutHostKeyRuleWritesNothing(t *testing.T) {
	af := newAdminFlake(t)
	const m = "m"

	if err := ensureInitrdKey(af.cfg, m); err == nil {
		t.Fatal("expected failure without a creation rule for the machine")
	}
	if fileExists(vars.MachineInitrdKeyPath(af.cfg.FlakeDir, m)) || fileExists(vars.MachineInitrdKeyPubPath(af.cfg.FlakeDir, m)) {
		t.Fatal("files left behind")
	}
}
