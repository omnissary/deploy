package cmd

import (
	"os"
	"strings"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func provisionWithoutZFS(t *testing.T, cfg *Config, machine string) {
	t.Helper()
	for _, step := range []func(*Config, string) error{ensureHostKey, ensureInitrdKey, ensureSecrets} {
		if err := step(cfg, machine); err != nil {
			t.Fatal(err)
		}
	}
	if err := syncAllRecipients(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestRequireMachinesProvisionedAcceptsProvisionedMachinesWithoutDecrypting(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	provisionWithoutZFS(t, af.cfg, "b")
	sopstest.UseIdentities(t)

	if err := requireMachinesProvisioned(af.cfg, "a", "b"); err != nil {
		t.Fatal(err)
	}
}

func TestRequireMachinesProvisionedRejectsUnprovisionedMachineAndCreatesNothing(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	conf := mustRead(t, af.cfg.SopsConf)

	err := requireMachinesProvisioned(af.cfg, "a", "new")
	if err == nil || !strings.Contains(err.Error(), "machine provision new") ||
		!strings.Contains(err.Error(), "vars/secrets/new.yaml") {
		t.Fatalf("expected hint for new, got %v", err)
	}
	for _, p := range vars.MachineFiles(af.cfg.FlakeDir, "new") {
		if fileExists(p) {
			t.Fatalf("%s created", p)
		}
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) {
		t.Fatal(".sops.yaml modified")
	}
}

func TestRequireMachinesProvisionedReportsSingleMissingFile(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	if err := os.Remove(vars.MachineInitrdKeyPubPath(af.cfg.FlakeDir, "a")); err != nil {
		t.Fatal(err)
	}

	err := requireMachinesProvisioned(af.cfg, "a")
	if err == nil || !strings.Contains(err.Error(), "initrd-ssh/id_ed25519.pub") || strings.Contains(err.Error(), "a.yaml") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestRequireMachinesProvisionedRejectsStaleRecipients(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	if err := writeGenericAdmins(af, sopstest.AddPGPKey(t)); err != nil {
		t.Fatal(err)
	}

	err := requireMachinesProvisioned(af.cfg, "a")
	if err == nil || !strings.Contains(err.Error(), "deploy sync") {
		t.Fatalf("expected sync hint, got %v", err)
	}
}

func TestRequireMachinesProvisionedRequiresSopsConf(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	if err := os.Remove(af.cfg.SopsConf); err != nil {
		t.Fatal(err)
	}
	if err := requireMachinesProvisioned(af.cfg, "a"); err == nil {
		t.Fatal("expected error without .sops.yaml")
	}
}
