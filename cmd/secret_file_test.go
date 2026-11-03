package cmd

import (
	"os"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func newTestConfig(fl sopstest.Flake) *Config {
	return &Config{FlakeDir: fl.Dir, SopsConf: fl.SopsConf}
}

func TestCreateEncryptedYAMLIfMissingCreatesEmptyEncryptedFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	cfg := newTestConfig(fl)
	path := vars.MachineSecretsPath(fl.Dir, "m")

	if err := createEncryptedYAMLIfMissing(cfg, path, "machine", "m"); err != nil {
		t.Fatalf("create: %v", err)
	}
	f, err := sops.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if keys := f.Keys(); len(keys) != 0 {
		t.Fatalf("keys = %v", keys)
	}
}

func TestCreateEncryptedYAMLIfMissingKeepsExistingFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	cfg := newTestConfig(fl)
	path := vars.MachineSecretsPath(fl.Dir, "m")
	if err := createEncryptedYAMLIfMissing(cfg, path, "machine", "m"); err != nil {
		t.Fatal(err)
	}
	if err := sops.Edit(path, func(f *sops.File) error { f.Set("k", "v"); return nil }); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	if err := createEncryptedYAMLIfMissing(cfg, path, "machine", "m"); err != nil {
		t.Fatalf("second create: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("existing secrets file was modified")
	}
}

func TestCreateEncryptedYAMLIfMissingLeavesNoStubOnFailure(t *testing.T) {
	fl := sopstest.NewFlake(t)
	sopstest.WriteConf(t, fl.SopsConf, sopstest.Rule{PathRegex: "^nothing$", Age: []string{fl.Identity.Public}})
	cfg := newTestConfig(fl)
	path := vars.MachineSecretsPath(fl.Dir, "m")

	if err := createEncryptedYAMLIfMissing(cfg, path, "machine", "m"); err == nil {
		t.Fatal("expected failure without a matching creation rule")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stub left behind at %s (stat err %v)", path, err)
	}
	if err := createEncryptedYAMLIfMissing(cfg, path, "machine", "m"); err == nil {
		t.Fatal("retry must fail again rather than treat a stub as existing")
	}
}
