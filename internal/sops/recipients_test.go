package sops

import (
	"os"
	"path/filepath"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
)

func TestNewRecipientsNormalises(t *testing.T) {
	t.Parallel()
	r := NewRecipients([]string{"abcd", " ABCD ", "", "1234"}, []string{"age1b", "age1a", "age1b", " "})
	want := Recipients{PGP: []string{"1234", "ABCD"}, Age: []string{"age1a", "age1b"}}
	if !r.Equal(want) {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestRecipientsEqual(t *testing.T) {
	t.Parallel()
	a := NewRecipients([]string{"A"}, []string{"age1x", "age1y"})
	if !a.Equal(NewRecipients([]string{"a"}, []string{"age1y", "age1x"})) {
		t.Fatal("order or case should not matter")
	}
	for _, b := range []Recipients{
		NewRecipients(nil, []string{"age1x", "age1y"}),
		NewRecipients([]string{"A"}, []string{"age1x"}),
		NewRecipients([]string{"A", "B"}, []string{"age1x", "age1y"}),
	} {
		if a.Equal(b) {
			t.Fatalf("%+v equal to %+v", a, b)
		}
	}
}

func TestReadRecipientsYAMLAndBinaryWithoutDecrypting(t *testing.T) {
	fl := sopstest.NewFlake(t)
	other := sopstest.NewIdentity(t)
	sopstest.WriteConf(t, fl.SopsConf, sopstest.Rule{PathRegex: ".*", Age: []string{fl.Identity.Public, other.Public}})
	yamlPath := newEncryptedYAML(t, fl, "s.yaml", "a: b\n")
	binPath := newEncryptedBinary(t, fl, "key", []byte("x"))
	sopstest.UseIdentities(t)

	want := NewRecipients(nil, []string{fl.Identity.Public, other.Public})
	for _, p := range []string{yamlPath, binPath} {
		got, err := ReadRecipients(p)
		if err != nil {
			t.Fatalf("ReadRecipients %s: %v", p, err)
		}
		if !got.Equal(want) {
			t.Fatalf("%s: got %+v, want %+v", p, got, want)
		}
	}
}

func TestReadRecipientsReflectsRekey(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: b\n")
	other := sopstest.NewIdentity(t)
	sopstest.WriteConf(t, fl.SopsConf, sopstest.Rule{PathRegex: ".*", Age: []string{other.Public, fl.Identity.Public}})
	if err := UpdateKeys(fl.SopsConf, path); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRecipients(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(NewRecipients(nil, []string{other.Public, fl.Identity.Public})) {
		t.Fatalf("got %+v", got)
	}
}

func TestReadRecipientsRejectsNonSopsFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.yaml")
	if err := os.WriteFile(plain, []byte("a: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{plain, filepath.Join(dir, "missing.yaml")} {
		if _, err := ReadRecipients(p); err == nil {
			t.Fatalf("accepted %s", p)
		}
	}
}
