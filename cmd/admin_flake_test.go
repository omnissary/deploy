package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	for _, bin := range []string{"gpg", "gpgconf", "ssh-to-age"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not in PATH", bin)
		}
	}

	session := sopstest.NewIdentity(t)
	sopstest.UseIdentities(t, session)

	gnupg, err := os.MkdirTemp("", "gpg")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupg)
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--kill", "gpg-agent").Run()
		_ = os.RemoveAll(gnupg)
	})
	gpg := func(args ...string) string {
		out, err := exec.Command("gpg", append([]string{"--batch", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	gpg("--quick-gen-key", "deploy-test <test@invalid>", "ed25519", "sign", "never")
	var fpr string
	for _, line := range strings.Split(gpg("--list-keys", "--with-colons"), "\n") {
		if f := strings.Split(line, ":"); len(f) > 9 && f[0] == "fpr" {
			fpr = f[9]
			break
		}
	}
	if fpr == "" {
		t.Fatal("no fingerprint for generated gpg key")
	}
	gpg("--quick-add-key", fpr, "cv25519", "encr", "never")

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
