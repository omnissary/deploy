package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
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

func TestDeploymentCredentialsAcceptsProvisionedMachinesWithoutDecrypting(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	provisionWithoutZFS(t, af.cfg, "b")
	sopstest.UseIdentities(t)

	if err := requireDeploymentCredentials(af.cfg, "a", "b"); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentCredentialsRejectsUnprovisionedMachineAndCreatesNothing(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	conf := mustRead(t, af.cfg.SopsConf)

	err := requireDeploymentCredentials(af.cfg, "a", "new")
	if err == nil || !strings.Contains(err.Error(), "machine provision new") ||
		!strings.Contains(err.Error(), "vars/secrets/new/openssh/ssh_host_ed25519_key") {
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

func TestDeploymentCredentialsReportsSingleMissingFile(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	if err := os.Remove(vars.MachineInitrdKeyPubPath(af.cfg.FlakeDir, "a")); err != nil {
		t.Fatal(err)
	}

	err := requireDeploymentCredentials(af.cfg, "a")
	if err == nil || !strings.Contains(err.Error(), "initrd-ssh/id_ed25519.pub") || strings.Contains(err.Error(), "a.yaml") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestDeploymentCredentialsRejectsStaleRecipients(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	if err := writeGenericAdmins(af, sopstest.AddPGPKey(t)); err != nil {
		t.Fatal(err)
	}

	err := requireDeploymentCredentials(af.cfg, "a")
	if err == nil || !strings.Contains(err.Error(), "deploy sync") {
		t.Fatalf("expected sync hint, got %v", err)
	}
}

func TestDeploymentCredentialsRequiresSopsConf(t *testing.T) {
	af := newAdminFlake(t)
	provisionWithoutZFS(t, af.cfg, "a")
	if err := os.Remove(af.cfg.SopsConf); err != nil {
		t.Fatal(err)
	}
	if err := requireDeploymentCredentials(af.cfg, "a"); err == nil {
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
	if err := requireDeploymentCredentials(af.cfg, "chip"); err != nil {
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

func TestDeploymentChecksActualSecretsWithoutPublicOrPKIInventory(t *testing.T) {
	af := newAdminFlake(t)
	meta := manifest.Machine{HostKey: true, RequiredSecrets: []manifest.SecretRef{{Name: "node", Key: "yggdrasil"}, {Name: "node", Key: "certificate"}}}
	af.cfg.machineInfo = func(string) (manifest.Machine, error) { return meta, nil }
	if err := provisionMachine(af.cfg, "node"); err != nil {
		t.Fatal(err)
	}
	path := vars.MachineSecretsPath(af.cfg.FlakeDir, "node")
	seedSecrets(t, path, map[string]string{"yggdrasil": "disposable fixture", "certificate": "disposable certificate"})
	before := mustRead(t, path)
	sopstest.UseIdentities(t)
	if err := requireDeploymentCredentials(af.cfg, "node"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, mustRead(t, path)) {
		t.Fatal("preflight modified secrets")
	}
	if fileExists(yggPublicPath(af.cfg, "node")) || fileExists(filepath.Join(af.cfg.FlakeDir, "vars", "admin", "pki")) {
		t.Fatal("preflight created inventory")
	}
}

func TestStalePublicProjectionDoesNotSatisfyRequiredSecret(t *testing.T) {
	af := newAdminFlake(t)
	af.cfg.machineInfo = func(string) (manifest.Machine, error) {
		return manifest.Machine{HostKey: true, RequiredSecrets: []manifest.SecretRef{{Name: "node", Key: "yggdrasil"}}}, nil
	}
	if err := provisionMachine(af.cfg, "node"); err != nil {
		t.Fatal(err)
	}
	public := yggPublicPath(af.cfg, "node")
	if err := os.MkdirAll(filepath.Dir(public), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(public, []byte(`{"address":"200::1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := requireDeploymentCredentials(af.cfg, "node"); err == nil || !strings.Contains(err.Error(), "missing required secret yggdrasil") {
		t.Fatalf("%v", err)
	}
}

func TestTargetOwnedKeysRequireNoControllerCredentials(t *testing.T) {
	cfg := &Config{FlakeDir: t.TempDir(), machineInfo: func(string) (manifest.Machine, error) { return manifest.Machine{}, nil }}
	if err := provisionMachine(cfg, "board"); err != nil {
		t.Fatal(err)
	}
	if err := requireDeploymentCredentials(cfg, "board"); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(cfg.FlakeDir)
	if err != nil || len(files) != 0 {
		t.Fatal("created controller state", err)
	}
}

func TestProvisionDoesNotGenerateApplicationResources(t *testing.T) {
	af := newAdminFlake(t)
	af.cfg.machineInfo = func(string) (manifest.Machine, error) {
		return manifest.Machine{HostKey: true, RequiredSecrets: []manifest.SecretRef{{Name: "node", Key: "yggdrasil"}}}, nil
	}
	if err := provisionMachine(af.cfg, "node"); err != nil {
		t.Fatal(err)
	}
	keys, err := sops.ListYAMLKeys(vars.MachineSecretsPath(af.cfg.FlakeDir, "node"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if key == "yggdrasil" {
			t.Fatal("provision generated an application identity")
		}
	}
}

func TestUnlockDoesNotDependOnApplicationOrHostCredentials(t *testing.T) {
	cfg, _ := setupFlakyAgeFlake(t, "node")
	seedSecrets(t, vars.MachineSecretsPath(cfg.FlakeDir, "node"), map[string]string{"root-key": "disposable"})
	meta := manifest.Machine{
		HostKey:         true,
		InitrdSSH:       true,
		Unlock:          "zfs",
		Pools:           map[string]manifest.Pool{"rpool": {Secret: "root-key", Format: "hex", KeyPath: "/run/root-key"}},
		RequiredSecrets: []manifest.SecretRef{{Name: "node", Key: "missing-application-key"}},
	}
	// Disable the only available decryption command before checking metadata.
	if err := os.Unsetenv("SOPS_AGE_KEY_CMD"); err != nil {
		t.Fatal(err)
	}
	if err := requireUnlockCredentials(cfg, "node", meta); err != nil {
		t.Fatal(err)
	}
	meta.Pools["rpool"] = manifest.Pool{Secret: "missing-root-key", Format: "hex", KeyPath: "/run/root-key"}
	if err := requireUnlockCredentials(cfg, "node", meta); err == nil {
		t.Fatal("accepted missing storage key")
	}
	meta.Unlock = "luks"
	if err := requireUnlockCredentials(cfg, "node", meta); err != nil {
		t.Fatal("interactive unlock required controller credentials", err)
	}
}
