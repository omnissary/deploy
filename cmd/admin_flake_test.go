package cmd

import (
	"os/exec"
	"path/filepath"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
)

type adminFlake struct {
	cfg     *Config
	pgp     string
	session sopstest.Identity
}

// newAdminFlake creates a flake initialised like `deploy init`: generic rules
// with a throwaway admin PGP key plus a session age key, which is the only
// identity available for decryption.
func newAdminFlake(t *testing.T) adminFlake {
	t.Helper()
	if _, err := exec.LookPath("ssh-to-age"); err != nil {
		t.Skip("ssh-to-age not in PATH")
	}

	session := sopstest.NewIdentity(t)
	sopstest.UseIdentities(t, session)
	fpr := sopstest.NewPGPKey(t)

	dir := t.TempDir()
	cfg := &Config{FlakeDir: dir, SopsConf: filepath.Join(dir, ".sops.yaml")}
	if err := sops.InitConf(cfg.SopsConf, []string{fpr}); err != nil {
		t.Fatalf("InitConf: %v", err)
	}
	if _, err := sops.AddSessionKey(cfg.SopsConf, dir, session.Public, sops.UpdateKeys); err != nil {
		t.Fatalf("AddSessionKey: %v", err)
	}
	return adminFlake{cfg: cfg, pgp: fpr, session: session}
}
