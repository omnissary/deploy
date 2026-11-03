package sops

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
)

func newEncryptedYAML(t *testing.T, fl sopstest.Flake, name, plain string) string {
	t.Helper()
	path := filepath.Join(fl.Dir, name)
	if err := os.WriteFile(path, []byte(plain), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptYAML(fl.SopsConf, path); err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}
	return path
}

func newEncryptedBinary(t *testing.T, fl sopstest.Flake, name string, plain []byte) string {
	t.Helper()
	path := filepath.Join(fl.Dir, name)
	out, err := EncryptBinary(fl.SopsConf, path, plain)
	if err != nil {
		t.Fatalf("EncryptBinary: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustOpen(t *testing.T, path string) *File {
	t.Helper()
	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return f
}

func mustGet(t *testing.T, path, key string) string {
	t.Helper()
	v, err := mustOpen(t, path).Get(key)
	if err != nil {
		t.Fatalf("Get %s: %v", key, err)
	}
	return v
}

func TestOpenRejectsMissingFile(t *testing.T) {
	sopstest.NewFlake(t)
	if _, err := Open(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("expected Open to fail for a missing file")
	}
}

func TestOpenRejectsPlaintextFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := filepath.Join(fl.Dir, "plain.yaml")
	if err := os.WriteFile(path, []byte("a: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected Open to fail for a file without sops metadata")
	}
}

func TestOpenWithoutIdentityFailsAndIsNotKeyNotFound(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: b\n")
	sopstest.UseIdentities(t)

	_, err := Open(path)
	if err == nil {
		t.Fatal("expected Open to fail without a matching identity")
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("decrypt failure must not wrap ErrKeyNotFound: %v", err)
	}
}

func TestOpenRejectsTamperedFileButOpenUnverifiedAccepts(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "keep: 1\ndrop: 2\n")

	var doc map[string]interface{}
	if err := yaml.Unmarshal(readFile(t, path), &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "drop")
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("expected Open to reject a file whose MAC no longer matches")
	}
	f, err := OpenUnverified(path)
	if err != nil {
		t.Fatalf("OpenUnverified: %v", err)
	}
	if got, _ := f.Get("keep"); got != "1" {
		t.Fatalf("unexpected value %q", got)
	}
}

func TestGetReturnsScalarsAndRejectsMissingAndNested(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "str: hello\nint: 5\nbool: true\nnested:\n  x: 1\nlist: [1, 2]\n")
	f := mustOpen(t, path)

	for key, want := range map[string]string{"str": "hello", "int": "5", "bool": "true"} {
		got, err := f.Get(key)
		if err != nil {
			t.Fatalf("Get %s: %v", key, err)
		}
		if got != want {
			t.Errorf("Get %s = %q, want %q", key, got, want)
		}
	}
	if _, err := f.Get("absent"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Get absent: expected ErrKeyNotFound, got %v", err)
	}
	for _, key := range []string{"nested", "list"} {
		if _, err := f.Get(key); err == nil || errors.Is(err, ErrKeyNotFound) {
			t.Errorf("Get %s: expected a non-scalar error, got %v", key, err)
		}
	}
}

func TestKeysAreSortedAndExcludeMetadata(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "zeta: 1\nalpha: 2\nmid: 3\n")

	got := mustOpen(t, path).Keys()
	if want := []string{"alpha", "mid", "zeta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Keys = %v, want %v", got, want)
	}
}

func TestKeysOfEmptyFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "{}\n")

	if got := mustOpen(t, path).Keys(); len(got) != 0 {
		t.Fatalf("Keys = %v, want none", got)
	}
}

func TestSetAddsAndReplacesKeepingOtherValues(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: one\nb: two\n")

	if err := Edit(path, func(f *File) error {
		f.Set("b", "TWO")
		f.Set("c", "three")
		return nil
	}); err != nil {
		t.Fatalf("Edit: %v", err)
	}

	f := mustOpen(t, path)
	for key, want := range map[string]string{"a": "one", "b": "TWO", "c": "three"} {
		if got, _ := f.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestDeleteRemovesOnlyThatKey(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: one\nb: two\nc: three\n")

	if err := Edit(path, func(f *File) error { return f.Delete("b") }); err != nil {
		t.Fatalf("Edit: %v", err)
	}

	f := mustOpen(t, path)
	if got := f.Keys(); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("Keys = %v", got)
	}
	if got, _ := f.Get("c"); got != "three" {
		t.Fatalf("c = %q", got)
	}
}

func TestDeleteMissingKeyFailsAndLeavesFileUntouched(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: one\n")
	before := readFile(t, path)

	err := Edit(path, func(f *File) error { return f.Delete("absent") })
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("file was rewritten")
	}
}

func TestSetIfAbsentCreatesMissingKey(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "other: x\n")

	var created bool
	if err := Edit(path, func(f *File) error {
		var err error
		created, err = f.SetIfAbsent("k", func() (string, error) { return "generated", nil })
		return err
	}); err != nil {
		t.Fatalf("Edit: %v", err)
	}
	if !created {
		t.Fatal("expected creation")
	}
	if got := mustGet(t, path, "k"); got != "generated" {
		t.Fatalf("k = %q", got)
	}
}

func TestSetIfAbsentKeepsExistingKeyWithoutRewriting(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "k: original\n")
	before := readFile(t, path)

	if err := Edit(path, func(f *File) error {
		created, err := f.SetIfAbsent("k", func() (string, error) {
			t.Fatal("generate called for an existing key")
			return "", nil
		})
		if created {
			t.Error("reported creation for an existing key")
		}
		return err
	}); err != nil {
		t.Fatalf("Edit: %v", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("file was rewritten")
	}
}

func TestSetIfAbsentGeneratorErrorLeavesFileUntouched(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "other: x\n")
	before := readFile(t, path)

	boom := errors.New("boom")
	err := Edit(path, func(f *File) error {
		_, err := f.SetIfAbsent("k", func() (string, error) { return "", boom })
		return err
	})
	if !errors.Is(err, boom) {
		t.Fatalf("expected generator error, got %v", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("file was rewritten")
	}
}

func TestEditCallbackErrorLeavesFileUntouched(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: one\n")
	before := readFile(t, path)

	boom := errors.New("boom")
	err := Edit(path, func(f *File) error {
		f.Set("a", "changed")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("expected callback error, got %v", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("file was rewritten")
	}
}

func TestSaveWithoutChangesDoesNotRewrite(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: one\n")
	before := readFile(t, path)

	f := mustOpen(t, path)
	if _, err := f.Get("a"); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("file was rewritten")
	}
}

func TestMarkDirtyForcesRewrite(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: one\n")
	before := readFile(t, path)

	f := mustOpen(t, path)
	f.MarkDirty()
	if err := f.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if bytes.Equal(before, readFile(t, path)) {
		t.Fatal("file was not rewritten")
	}
	if got := mustGet(t, path, "a"); got != "one" {
		t.Fatalf("a = %q", got)
	}
}

func TestSaveTwiceFails(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: one\n")

	f := mustOpen(t, path)
	f.Set("a", "two")
	if err := f.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := f.Save(); err == nil {
		t.Fatal("expected second Save to fail")
	}
}

func TestSaveLeavesNoTempFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: one\n")

	if err := Edit(path, func(f *File) error { f.Set("a", "two"); return nil }); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
}

func TestBytesRoundTripsBinaryFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	plain := []byte("-----BEGIN KEY-----\n\x00\xff binary \r\n-----END KEY-----\n")
	path := newEncryptedBinary(t, fl, "key", plain)

	got, err := mustOpen(t, path).Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("Bytes = %q, want %q", got, plain)
	}
}

func TestRekeyAddsAndRemovesRecipientsKeepingValues(t *testing.T) {
	fl := sopstest.NewFlake(t)
	a := fl.Identity
	b := sopstest.NewIdentity(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "k: v\n")

	sopstest.WriteConf(t, fl.SopsConf, sopstest.Rule{PathRegex: ".*", Age: []string{a.Public, b.Public}})
	if err := Edit(path, func(f *File) error { return f.Rekey(fl.SopsConf) }); err != nil {
		t.Fatalf("Rekey add: %v", err)
	}
	sopstest.UseIdentities(t, b)
	if got := mustGet(t, path, "k"); got != "v" {
		t.Fatalf("b reads %q", got)
	}

	sopstest.WriteConf(t, fl.SopsConf, sopstest.Rule{PathRegex: ".*", Age: []string{b.Public}})
	if err := Edit(path, func(f *File) error { return f.Rekey(fl.SopsConf) }); err != nil {
		t.Fatalf("Rekey remove: %v", err)
	}
	sopstest.UseIdentities(t, a)
	if _, err := Open(path); err == nil {
		t.Fatal("removed recipient can still decrypt")
	}
}

func TestRekeyFailsWithoutMatchingRuleAndLeavesFileUntouched(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "k: v\n")
	before := readFile(t, path)

	sopstest.WriteConf(t, fl.SopsConf, sopstest.Rule{PathRegex: "^nothing-matches$", Age: []string{fl.Identity.Public}})
	if err := Edit(path, func(f *File) error { return f.Rekey(fl.SopsConf) }); err == nil {
		t.Fatal("expected Rekey to fail without a matching creation rule")
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("file was rewritten")
	}
}
