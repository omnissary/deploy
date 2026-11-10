package cmd

import (
	"os"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func TestYggdrasilEnsurePreservesIdentityAndRotationIsExplicit(t *testing.T) {
	af := newAdminFlake(t)
	if err := ensureSecrets(af.cfg, "m"); err != nil {
		t.Fatal(err)
	}
	first, err := provisionYggdrasil(af.cfg, "m", false)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(vars.MachineSecretsPath(af.cfg.FlakeDir, "m"))
	again, err := provisionYggdrasil(af.cfg, "m", false)
	if err != nil || first != again {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(vars.MachineSecretsPath(af.cfg.FlakeDir, "m"))
	if string(before) != string(after) {
		t.Fatal("ensure rewrote private identity")
	}
	rotated, err := provisionYggdrasil(af.cfg, "m", true)
	if err != nil || first == rotated {
		t.Fatal(err)
	}
	if err := sops.Edit(vars.MachineSecretsPath(af.cfg.FlakeDir, "m"), func(f *sops.File) error {
		f.Set("yggdrasil", "corrupt")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := provisionYggdrasil(af.cfg, "m", true); err == nil {
		t.Fatal("rotation accepted corrupted identity")
	}
}
