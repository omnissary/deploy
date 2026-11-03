package sops

import (
	"bytes"
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
)

func tamper(t *testing.T, path, dropKey string) {
	t.Helper()
	var doc map[string]interface{}
	if err := yaml.Unmarshal(readFile(t, path), &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, dropKey)
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadFileReturnsBinaryPlaintext(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedBinary(t, fl, "key", []byte("pem\n"))

	got, err := ReadFile(path)
	if err != nil || !bytes.Equal(got, []byte("pem\n")) {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
	sopstest.UseIdentities(t)
	if _, err := ReadFile(path); err == nil {
		t.Fatal("expected failure without identity")
	}
}

func TestVerify(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: 1\nb: 2\n")

	if err := Verify(path); err != nil {
		t.Fatalf("Verify intact file: %v", err)
	}
	tamper(t, path, "b")
	if err := Verify(path); err == nil {
		t.Fatal("Verify accepted a tampered file")
	}
}

func TestRepairRestoresValidMACAndKeepsRemainingValues(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: 1\nb: 2\n")
	tamper(t, path, "b")

	if err := Repair(fl.SopsConf, path); err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if err := Verify(path); err != nil {
		t.Fatalf("Verify after repair: %v", err)
	}
	if got := mustOpen(t, path).Keys(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("keys = %v", got)
	}
}

func TestRepairFailsWithoutIdentityAndLeavesFileUntouched(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: 1\nb: 2\n")
	tamper(t, path, "b")
	before := readFile(t, path)
	sopstest.UseIdentities(t)

	if err := Repair(fl.SopsConf, path); err == nil {
		t.Fatal("expected Repair to fail without identity")
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("file modified")
	}
}

func TestUpdateKeysWithUnchangedRulesKeepsFileDecryptable(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newEncryptedYAML(t, fl, "s.yaml", "a: 1\n")

	if err := UpdateKeys(fl.SopsConf, path); err != nil {
		t.Fatalf("UpdateKeys: %v", err)
	}
	if got := mustGet(t, path, "a"); got != "1" {
		t.Fatalf("a = %q", got)
	}
}
