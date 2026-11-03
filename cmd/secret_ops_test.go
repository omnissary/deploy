package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
)

func newSecretsFile(t *testing.T, fl sopstest.Flake, name string, values map[string]string) string {
	t.Helper()
	path := filepath.Join(fl.Dir, name+".yaml")
	if err := sops.Create(fl.SopsConf, path, []byte("{}\n")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sops.Edit(path, func(f *sops.File) error {
		for k, v := range values {
			f.Set(k, v)
		}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return path
}

func secretValues(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := sops.Open(path)
	if err != nil {
		t.Fatalf("Open %s: %v", path, err)
	}
	out := map[string]string{}
	for _, k := range f.Keys() {
		v, err := f.Get(k)
		if err != nil {
			t.Fatal(err)
		}
		out[k] = v
	}
	return out
}

func fileBytes(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGetSecret(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newSecretsFile(t, fl, "m", map[string]string{"k": "v\n"})

	got, err := getSecret(path, "k")
	if err != nil || got != "v\n" {
		t.Fatalf("getSecret = %q, %v", got, err)
	}
	if _, err := getSecret(path, "absent"); !errors.Is(err, sops.ErrKeyNotFound) {
		t.Fatalf("missing key: expected ErrKeyNotFound, got %v", err)
	}
	if _, err := getSecret(filepath.Join(fl.Dir, "absent.yaml"), "k"); err == nil {
		t.Fatal("missing file: expected error")
	}
	sopstest.UseIdentities(t)
	if _, err := getSecret(path, "k"); err == nil || errors.Is(err, sops.ErrKeyNotFound) {
		t.Fatalf("undecryptable: expected a decrypt error, got %v", err)
	}
}

func TestSetSecretAddsAndOverwritesKeepingOthers(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newSecretsFile(t, fl, "m", map[string]string{"rootfs": "keep", "k": "old"})

	if err := setSecret(path, "k", "new"); err != nil {
		t.Fatal(err)
	}
	if err := setSecret(path, "added", "x"); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"rootfs": "keep", "k": "new", "added": "x"}
	if got := secretValues(t, path); !reflect.DeepEqual(got, want) {
		t.Fatalf("values = %v, want %v", got, want)
	}
}

func TestSetSecretRequiresExistingFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := filepath.Join(fl.Dir, "absent.yaml")
	if err := setSecret(path, "k", "v"); err == nil {
		t.Fatal("expected error for missing file")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("setSecret created a file")
	}
}

func TestSetSecretUndecryptableLeavesFileUntouched(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newSecretsFile(t, fl, "m", map[string]string{"rootfs": "keep"})
	before := fileBytes(t, path)
	sopstest.UseIdentities(t)

	if err := setSecret(path, "k", "v"); err == nil {
		t.Fatal("expected decrypt error")
	}
	if fileBytes(t, path) != before {
		t.Fatal("file modified")
	}
}

func TestDeleteSecret(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newSecretsFile(t, fl, "m", map[string]string{"rootfs": "keep", "k": "v"})

	if err := deleteSecret(path, "k"); err != nil {
		t.Fatal(err)
	}
	if got := secretValues(t, path); !reflect.DeepEqual(got, map[string]string{"rootfs": "keep"}) {
		t.Fatalf("values = %v", got)
	}
	before := fileBytes(t, path)
	if err := deleteSecret(path, "k"); !errors.Is(err, sops.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if fileBytes(t, path) != before {
		t.Fatal("file modified by failed delete")
	}
}

func TestMoveSecretRenameWithinFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newSecretsFile(t, fl, "m", map[string]string{"rootfs": "keep", "old": "v"})

	if err := moveSecret(path, "old", path, "new", false); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"rootfs": "keep", "new": "v"}
	if got := secretValues(t, path); !reflect.DeepEqual(got, want) {
		t.Fatalf("values = %v, want %v", got, want)
	}
}

func TestMoveSecretIdenticalSourceAndDestinationIsRejected(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newSecretsFile(t, fl, "m", map[string]string{"k": "v"})
	before := fileBytes(t, path)

	if err := moveSecret(path, "k", path, "k", false); err == nil {
		t.Fatal("expected error")
	}
	if fileBytes(t, path) != before {
		t.Fatal("file modified")
	}
}

func TestMoveSecretMissingSourceKeyWithinFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newSecretsFile(t, fl, "m", map[string]string{"k": "v"})
	before := fileBytes(t, path)

	if err := moveSecret(path, "absent", path, "new", false); !errors.Is(err, sops.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if fileBytes(t, path) != before {
		t.Fatal("file modified")
	}
}

func TestMoveSecretAcrossFiles(t *testing.T) {
	fl := sopstest.NewFlake(t)
	src := newSecretsFile(t, fl, "a", map[string]string{"k": "v", "stay": "s"})
	dst := newSecretsFile(t, fl, "b", map[string]string{"other": "o"})

	if err := moveSecret(src, "k", dst, "k2", false); err != nil {
		t.Fatal(err)
	}
	if got := secretValues(t, src); !reflect.DeepEqual(got, map[string]string{"stay": "s"}) {
		t.Fatalf("src = %v", got)
	}
	if got := secretValues(t, dst); !reflect.DeepEqual(got, map[string]string{"other": "o", "k2": "v"}) {
		t.Fatalf("dst = %v", got)
	}
}

func TestMoveSecretAcrossFilesMissingSourceKeyTouchesNothing(t *testing.T) {
	fl := sopstest.NewFlake(t)
	src := newSecretsFile(t, fl, "a", map[string]string{"k": "v"})
	dst := newSecretsFile(t, fl, "b", map[string]string{"other": "o"})
	srcBefore, dstBefore := fileBytes(t, src), fileBytes(t, dst)

	if err := moveSecret(src, "absent", dst, "x", false); !errors.Is(err, sops.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if fileBytes(t, src) != srcBefore || fileBytes(t, dst) != dstBefore {
		t.Fatal("files modified")
	}
}

func TestMoveSecretAcrossFilesKeepsSourceWhenDestinationFails(t *testing.T) {
	fl := sopstest.NewFlake(t)
	src := newSecretsFile(t, fl, "a", map[string]string{"k": "v"})
	srcBefore := fileBytes(t, src)

	if err := moveSecret(src, "k", filepath.Join(fl.Dir, "missing.yaml"), "k", false); err == nil {
		t.Fatal("expected error for missing destination file")
	}
	if fileBytes(t, src) != srcBefore {
		t.Fatal("source modified although destination write failed")
	}
}

func TestMoveSecretRefusesExistingDestinationKeyWithinFile(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newSecretsFile(t, fl, "m", map[string]string{"a": "1", "b": "2"})
	before := fileBytes(t, path)

	if err := moveSecret(path, "a", path, "b", false); err == nil {
		t.Fatal("expected refusal to overwrite")
	}
	if fileBytes(t, path) != before {
		t.Fatal("file modified")
	}
}

func TestMoveSecretOverwritesWithinFileWhenForced(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newSecretsFile(t, fl, "m", map[string]string{"a": "1", "b": "2"})

	if err := moveSecret(path, "a", path, "b", true); err != nil {
		t.Fatal(err)
	}
	if got := secretValues(t, path); !reflect.DeepEqual(got, map[string]string{"b": "1"}) {
		t.Fatalf("values = %v", got)
	}
}

func TestMoveSecretRefusesExistingDestinationKeyAcrossFiles(t *testing.T) {
	fl := sopstest.NewFlake(t)
	src := newSecretsFile(t, fl, "a", map[string]string{"k": "new"})
	dst := newSecretsFile(t, fl, "b", map[string]string{"k": "precious"})
	srcBefore, dstBefore := fileBytes(t, src), fileBytes(t, dst)

	if err := moveSecret(src, "k", dst, "k", false); err == nil {
		t.Fatal("expected refusal to overwrite")
	}
	if fileBytes(t, src) != srcBefore || fileBytes(t, dst) != dstBefore {
		t.Fatal("files modified")
	}
}

func TestMoveSecretOverwritesAcrossFilesWhenForced(t *testing.T) {
	fl := sopstest.NewFlake(t)
	src := newSecretsFile(t, fl, "a", map[string]string{"k": "new"})
	dst := newSecretsFile(t, fl, "b", map[string]string{"k": "old"})

	if err := moveSecret(src, "k", dst, "k", true); err != nil {
		t.Fatal(err)
	}
	if got := secretValues(t, dst); !reflect.DeepEqual(got, map[string]string{"k": "new"}) {
		t.Fatalf("dst = %v", got)
	}
	if got := secretValues(t, src); len(got) != 0 {
		t.Fatalf("src = %v", got)
	}
}
