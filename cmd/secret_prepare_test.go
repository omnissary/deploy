package cmd

import (
	"strings"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func machineTarget(cfg *Config, m string) *secretTarget {
	return &secretTarget{name: m, path: vars.MachineSecretsPath(cfg.FlakeDir, m), kind: targetMachine}
}

func groupTarget(cfg *Config, g string) *secretTarget {
	return &secretTarget{name: g, path: vars.SharedSecretsPath(cfg.FlakeDir, g), kind: targetGroup}
}

func TestPrepareSecretFileRequiresHostKeyAndGeneratesNothing(t *testing.T) {
	af := newAdminFlake(t)
	conf := mustRead(t, af.cfg.SopsConf)
	target := machineTarget(af.cfg, "m")

	err := prepareSecretFile(af.cfg, target)
	if err == nil || !strings.Contains(err.Error(), "machine provision m") {
		t.Fatalf("expected provisioning hint, got %v", err)
	}
	for _, p := range []string{target.path, vars.MachineHostKeyPath(af.cfg.FlakeDir, "m"), vars.MachineHostKeyPubPath(af.cfg.FlakeDir, "m")} {
		if fileExists(p) {
			t.Fatalf("%s created", p)
		}
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) {
		t.Fatal(".sops.yaml modified")
	}
}

func TestPrepareSecretFileCreatesMachineFileForProvisionedMachine(t *testing.T) {
	af := newAdminFlake(t)
	if err := ensureHostKey(af.cfg, "m"); err != nil {
		t.Fatal(err)
	}
	target := machineTarget(af.cfg, "m")

	if err := prepareSecretFile(af.cfg, target); err != nil {
		t.Fatal(err)
	}
	if !containsFold(recipientsOf(t, target.path).Age, machineAge(t, af.cfg, "m")) {
		t.Fatal("new secrets file not encrypted for the machine")
	}
}

func TestPrepareSecretFileCreatesGroupFile(t *testing.T) {
	af := newAdminFlake(t)
	target := groupTarget(af.cfg, "g")
	if err := prepareSecretFile(af.cfg, target); err != nil {
		t.Fatal(err)
	}
	if !fileExists(target.path) {
		t.Fatal("group file not created")
	}
}

func TestPrepareSecretFileRefusesNewFileWhileRecipientsAreStale(t *testing.T) {
	af := newAdminFlake(t)
	if err := ensureHostKey(af.cfg, "m"); err != nil {
		t.Fatal(err)
	}
	if err := writeGenericAdmins(af, sopstest.AddPGPKey(t)); err != nil {
		t.Fatal(err)
	}
	target := machineTarget(af.cfg, "m")

	err := prepareSecretFile(af.cfg, target)
	if err == nil || !strings.Contains(err.Error(), "deploy sync") {
		t.Fatalf("expected sync hint, got %v", err)
	}
	if fileExists(target.path) {
		t.Fatal("file created with stale recipients")
	}
}

func TestPrepareSecretFileLeavesExistingFileAlone(t *testing.T) {
	af := newAdminFlake(t)
	secrets := newMachineWithSecret(t, af, "m")
	if err := writeGenericAdmins(af, sopstest.AddPGPKey(t)); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, secrets)

	if err := prepareSecretFile(af.cfg, machineTarget(af.cfg, "m")); err != nil {
		t.Fatalf("existing file must not require sync: %v", err)
	}
	if string(before) != string(mustRead(t, secrets)) {
		t.Fatal("existing file modified")
	}
	if err := setSecret(secrets, "k2", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, err := getSecret(secrets, "k"); err != nil || v != "v" {
		t.Fatalf("existing value lost: %q, %v", v, err)
	}
}
