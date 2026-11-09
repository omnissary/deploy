package sops

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
)

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

func TestCreateYAMLRoundTrips(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := filepath.Join(fl.Dir, "s.yaml")

	if err := Create(fl.SopsConf, path, []byte("a: one\n")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := mustGet(t, path, "a"); got != "one" {
		t.Fatalf("a = %q", got)
	}
	if bytes.Contains(readFile(t, path), []byte("one")) {
		t.Fatal("plaintext value found in encrypted file")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCreateBinaryRoundTrips(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := filepath.Join(fl.Dir, "key")
	plain := []byte("secret\x00bytes\n")

	if err := Create(fl.SopsConf, path, plain); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := mustOpen(t, path).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("Bytes = %q", got)
	}
}

func TestCreateUsesMatchingRuleRecipients(t *testing.T) {
	fl := sopstest.NewFlake(t)
	other := sopstest.NewIdentity(t)
	sopstest.WriteConf(t, fl.SopsConf,
		sopstest.Rule{PathRegex: `other\.yaml$`, Age: []string{other.Public}},
		sopstest.Rule{PathRegex: ".*", Age: []string{fl.Identity.Public}},
	)
	path := filepath.Join(fl.Dir, "other.yaml")

	if err := Create(fl.SopsConf, path, []byte("a: b\n")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("identity outside the matching rule can decrypt")
	}
	sopstest.UseIdentities(t, other)
	if got := mustGet(t, path, "a"); got != "b" {
		t.Fatalf("a = %q", got)
	}
}

func TestCreateRefusesToOverwrite(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: original\n")
	before := readFile(t, path)

	err := Create(fl.SopsConf, path, []byte("a: replaced\n"))
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected os.ErrExist, got %v", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("existing file was modified")
	}
	if got := dirEntries(t, fl.Dir); len(got) != 2 {
		t.Fatalf("unexpected leftovers %v", got)
	}
}

func TestCreateWithoutMatchingRuleWritesNothing(t *testing.T) {
	fl := sopstest.NewFlake(t)
	sopstest.WriteConf(t, fl.SopsConf, sopstest.Rule{PathRegex: "^nothing$", Age: []string{fl.Identity.Public}})
	dir := filepath.Join(fl.Dir, "out")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Create(fl.SopsConf, filepath.Join(dir, "s.yaml"), []byte("a: b\n")); err == nil {
		t.Fatal("expected Create to fail without a matching rule")
	}
	if got := dirEntries(t, dir); len(got) != 0 {
		t.Fatalf("files left behind: %v", got)
	}
}

func TestCreateRejectsInvalidYAMLAndWritesNothing(t *testing.T) {
	fl := sopstest.NewFlake(t)
	dir := filepath.Join(fl.Dir, "out")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Create(fl.SopsConf, filepath.Join(dir, "s.yaml"), []byte("a: [unterminated\n")); err == nil {
		t.Fatal("expected Create to reject invalid YAML")
	}
	if got := dirEntries(t, dir); len(got) != 0 {
		t.Fatalf("files left behind: %v", got)
	}
}

func TestCreateFailsForMissingDirectory(t *testing.T) {
	fl := sopstest.NewFlake(t)
	if err := Create(fl.SopsConf, filepath.Join(fl.Dir, "missing", "s.yaml"), []byte("{}\n")); err == nil {
		t.Fatal("expected Create to fail when the parent directory is missing")
	}
}
