package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSecretFilesListsMachineAndGroupFilesOnly(t *testing.T) {
	t.Parallel()
	cfg := &Config{FlakeDir: t.TempDir()}
	touch(t, vars.MachineSecretsPath(cfg.FlakeDir, "web"))
	touch(t, vars.MachineSecretsPath(cfg.FlakeDir, "db"))
	touch(t, vars.SharedSecretsPath(cfg.FlakeDir, "edge"))
	touch(t, vars.MachineHostKeyPath(cfg.FlakeDir, "web"))
	touch(t, filepath.Join(cfg.FlakeDir, "vars", "secrets", "notes.txt"))
	touch(t, filepath.Join(vars.AdminDir(cfg.FlakeDir), "x.yaml"))

	files, err := secretFiles(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []secretFile{
		{name: "db", path: vars.MachineSecretsPath(cfg.FlakeDir, "db")},
		{name: "edge", path: vars.SharedSecretsPath(cfg.FlakeDir, "edge")},
		{name: "web", path: vars.MachineSecretsPath(cfg.FlakeDir, "web")},
	}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("files = %+v\nwant %+v", files, want)
	}
	if got := completionExistingTargetNames(cfg); !reflect.DeepEqual(got, []string{"db", "edge", "web"}) {
		t.Fatalf("names = %v", got)
	}
}

func TestSecretFilesEmptyFlake(t *testing.T) {
	t.Parallel()
	cfg := &Config{FlakeDir: t.TempDir()}
	files, err := secretFiles(cfg)
	if err != nil || len(files) != 0 {
		t.Fatalf("files = %v, %v", files, err)
	}
	if err := listAllSecrets(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSortedUnique(t *testing.T) {
	t.Parallel()
	if got := sortedUnique([]string{"b", "a", "b", "c", "a"}); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("got %v", got)
	}
	if got := sortedUnique(nil); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}
