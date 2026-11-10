package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
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

func TestNoInitrdSSHKeysRequiredForDisabledCapability(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "chip")
	af.cfg.machineInfo = func(string) (manifest.Machine, error) {
		return manifest.Machine{HostKey: true}, nil
	}
	for _, p := range []string{vars.MachineInitrdKeyPath(af.cfg.FlakeDir, "chip"), vars.MachineInitrdKeyPubPath(af.cfg.FlakeDir, "chip")} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := requireMachinesProvisioned(af.cfg, "chip"); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionDoesNotCreateDisabledInitrdSSHKeys(t *testing.T) {
	af := newAdminFlake(t)
	af.cfg.machineInfo = func(string) (manifest.Machine, error) {
		return manifest.Machine{HostKey: true}, nil
	}
	if err := provisionMachine(af.cfg, "chip"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{vars.MachineInitrdKeyPath(af.cfg.FlakeDir, "chip"), vars.MachineInitrdKeyPubPath(af.cfg.FlakeDir, "chip")} {
		if fileExists(path) {
			t.Fatalf("disabled initrd SSH key created: %s", path)
		}
	}
	if !fileExists(vars.MachineHostKeyPath(af.cfg.FlakeDir, "chip")) {
		t.Fatal("host key missing")
	}
}

func TestProvisionDeclaredResourcesAndReadOnlyPrerequisites(t *testing.T) {
	af := newAdminFlake(t)
	meta := manifest.Machine{HostKey: true, Yggdrasil: true, Certificates: []string{"client"}}
	af.cfg.machineInfo = func(string) (manifest.Machine, error) { return meta, nil }
	spec := manifest.Certificate{
		Issuer:  "root",
		Subject: "client",
		Usage:   []string{"clientAuth"},
		Target:  manifest.Target{Name: "m", Cert: "cert", Key: "key", CA: "ca"},
	}
	af.cfg.manifestInfo = func() (manifest.Manifest, error) {
		return manifest.Manifest{SchemaVersion: 1, Certificates: map[string]manifest.Certificate{"client": spec}}, nil
	}
	if _, err := pkiStore(af.cfg).Create("root", manifest.Authority{}); err != nil {
		t.Fatal(err)
	}
	if err := provisionMachine(af.cfg, "m"); err != nil {
		t.Fatal(err)
	}
	if fileExists(vars.MachineInitrdKeyPath(af.cfg.FlakeDir, "m")) {
		t.Fatal("board gained an initrd key")
	}
	before, err := os.ReadFile(vars.MachineSecretsPath(af.cfg.FlakeDir, "m"))
	if err != nil {
		t.Fatal(err)
	}
	if err := provisionMachine(af.cfg, "m"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(vars.MachineSecretsPath(af.cfg.FlakeDir, "m"))
	if string(before) != string(after) {
		t.Fatal("idempotent provisioning changed credentials")
	}
	sopstest.UseIdentities(t)
	if err := requireMachinesProvisioned(af.cfg, "m"); err != nil {
		t.Fatalf("prerequisite check needed a decryption key: %v", err)
	}
}

func TestProvisionRemovesOnlyPreviouslyManagedMemberships(t *testing.T) {
	af := newAdminFlake(t)
	af.cfg.HostsFile = filepath.Join(af.cfg.FlakeDir, "hosts")
	writeFlake(t, af.cfg.FlakeDir, `{ outputs = _: { nixosConfigurations.m = {}; }; }`)
	if err := ensureSecrets(af.cfg, "m"); err != nil {
		t.Fatal(err)
	}
	if _, err := hosts.AddMembers(af.cfg.HostsFile, "manual", []string{"m"}); err != nil {
		t.Fatal(err)
	}
	meta := manifest.Machine{Groups: []string{"managed"}}
	if err := provisionApplicationResources(af.cfg, "m", meta); err != nil {
		t.Fatal(err)
	}
	if err := provisionApplicationResources(af.cfg, "m", manifest.Machine{}); err != nil {
		t.Fatal(err)
	}
	managed, err := hosts.GroupMembers(af.cfg.HostsFile, "managed")
	if err != nil || len(managed) != 0 {
		t.Fatal(managed, err)
	}
	manual, err := hosts.GroupMembers(af.cfg.HostsFile, "manual")
	if err != nil || len(manual) != 1 {
		t.Fatal(manual, err)
	}
}
