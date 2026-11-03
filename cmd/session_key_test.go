package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/agekey"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func sessionIdentity(t *testing.T, cfg *Config, name string) sopstest.Identity {
	t.Helper()
	priv, err := sops.ReadFile(vars.SessionKeyPath(cfg.FlakeDir, name))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := agekey.PublicFromPrivate(string(priv))
	if err != nil {
		t.Fatal(err)
	}
	return sopstest.Identity{Private: string(priv), Public: pub}
}

func newMachineWithSecret(t *testing.T, af adminFlake, m string) string {
	t.Helper()
	if err := ensureHostKey(af.cfg, m); err != nil {
		t.Fatal(err)
	}
	path := vars.MachineSecretsPath(af.cfg.FlakeDir, m)
	if err := createEncryptedYAMLIfMissing(af.cfg, path, "machine", m); err != nil {
		t.Fatal(err)
	}
	if err := setSecret(path, "k", "v"); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnsureSessionKeyGeneratesAndGrantsAccess(t *testing.T) {
	af := newAdminFlake(t)
	secrets := newMachineWithSecret(t, af, "m")

	if err := ensureSessionKey(af.cfg, "dev"); err != nil {
		t.Fatalf("ensureSessionKey: %v", err)
	}
	id := sessionIdentity(t, af.cfg, "dev")
	if got := strings.TrimSpace(string(mustRead(t, vars.SessionKeyPubPath(af.cfg.FlakeDir, "dev")))); got != id.Public {
		t.Fatalf("public key file %q does not match private key %q", got, id.Public)
	}
	if !strings.Contains(string(mustRead(t, af.cfg.SopsConf)), id.Public) {
		t.Fatal("session key missing from .sops.yaml")
	}

	sopstest.UseIdentities(t, id)
	if v, err := getSecret(secrets, "k"); err != nil || v != "v" {
		t.Fatalf("new session key cannot read existing secrets: %q, %v", v, err)
	}
}

func TestEnsureSessionKeyIsIdempotent(t *testing.T) {
	af := newAdminFlake(t)
	if err := ensureSessionKey(af.cfg, "dev"); err != nil {
		t.Fatal(err)
	}
	priv := mustRead(t, vars.SessionKeyPath(af.cfg.FlakeDir, "dev"))
	conf := mustRead(t, af.cfg.SopsConf)

	if err := ensureSessionKey(af.cfg, "dev"); err != nil {
		t.Fatal(err)
	}
	if string(priv) != string(mustRead(t, vars.SessionKeyPath(af.cfg.FlakeDir, "dev"))) {
		t.Fatal("private key rewritten")
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) {
		t.Fatal(".sops.yaml rewritten")
	}
}

func TestEnsureSessionKeyWithMissingPublicKeyKeepsPrivateKey(t *testing.T) {
	af := newAdminFlake(t)
	if err := ensureSessionKey(af.cfg, "dev"); err != nil {
		t.Fatalf("ensureSessionKey: %v", err)
	}
	privPath := vars.SessionKeyPath(af.cfg.FlakeDir, "dev")
	pubPath := vars.SessionKeyPubPath(af.cfg.FlakeDir, "dev")
	privBefore := mustRead(t, privPath)
	pubBefore := mustRead(t, pubPath)
	if err := os.Remove(pubPath); err != nil {
		t.Fatal(err)
	}

	if err := ensureSessionKey(af.cfg, "dev"); err != nil {
		t.Fatalf("ensureSessionKey: %v", err)
	}
	if string(mustRead(t, privPath)) != string(privBefore) {
		t.Fatal("existing encrypted session key was overwritten")
	}
	if string(mustRead(t, pubPath)) != string(pubBefore) {
		t.Fatal("public key not restored identically")
	}
}

func TestEnsureSessionKeyWithMissingPrivateKeyFails(t *testing.T) {
	af := newAdminFlake(t)
	if err := ensureSessionKey(af.cfg, "dev"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(vars.SessionKeyPath(af.cfg.FlakeDir, "dev")); err != nil {
		t.Fatal(err)
	}
	if err := ensureSessionKey(af.cfg, "dev"); err == nil {
		t.Fatal("expected error")
	}
	if fileExists(vars.SessionKeyPath(af.cfg.FlakeDir, "dev")) {
		t.Fatal("a new private key was generated")
	}
}

func TestSessionKeyCommandsRejectUnsafeNames(t *testing.T) {
	af := newAdminFlake(t)
	conf := mustRead(t, af.cfg.SopsConf)
	for _, name := range []string{"", "../../escape", "a/b", "Upper", ".hidden"} {
		if err := ensureSessionKey(af.cfg, name); err == nil {
			t.Errorf("ensureSessionKey accepted %q", name)
		}
		if err := unlockSessionKey(af.cfg, name); err == nil {
			t.Errorf("unlockSessionKey accepted %q", name)
		}
		if err := removeSessionKey(af.cfg, name); err == nil {
			t.Errorf("removeSessionKey accepted %q", name)
		}
	}
	if _, err := os.Stat(filepath.Join(af.cfg.FlakeDir, "..", "escape-age-key")); !os.IsNotExist(err) {
		t.Fatal("file written outside vars/admin")
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) {
		t.Fatal(".sops.yaml modified")
	}
}

func TestRemoveSessionKeyRevokesAccess(t *testing.T) {
	af := newAdminFlake(t)
	secrets := newMachineWithSecret(t, af, "m")
	if err := ensureSessionKey(af.cfg, "dev"); err != nil {
		t.Fatal(err)
	}
	id := sessionIdentity(t, af.cfg, "dev")

	if err := removeSessionKey(af.cfg, "dev"); err != nil {
		t.Fatalf("removeSessionKey: %v", err)
	}
	if strings.Contains(string(mustRead(t, af.cfg.SopsConf)), id.Public) {
		t.Fatal("session key still in .sops.yaml")
	}
	if fileExists(vars.SessionKeyPath(af.cfg.FlakeDir, "dev")) || fileExists(vars.SessionKeyPubPath(af.cfg.FlakeDir, "dev")) {
		t.Fatal("session key files not deleted")
	}
	sopstest.UseIdentities(t, id)
	if _, err := getSecret(secrets, "k"); err == nil {
		t.Fatal("removed session key can still decrypt")
	}
}

func TestRemoveUnknownSessionKeyFails(t *testing.T) {
	af := newAdminFlake(t)
	conf := mustRead(t, af.cfg.SopsConf)
	if err := removeSessionKey(af.cfg, "nope"); err == nil {
		t.Fatal("expected error")
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) {
		t.Fatal(".sops.yaml modified")
	}
}
