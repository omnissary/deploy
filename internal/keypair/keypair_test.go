package keypair

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
)

type recorder struct {
	generated, derived, prepared int
	preparedPub                  []byte
	privAtPrepare                bool
}

func newSpec(t *testing.T, fl sopstest.Flake, r *recorder) Spec {
	t.Helper()
	dir := filepath.Join(fl.Dir, "keys", "m")
	s := Spec{
		Name: "m test key",
		Priv: filepath.Join(dir, "id"),
		Pub:  filepath.Join(dir, "id.pub"),
	}
	s.Generate = func() ([]byte, []byte, error) {
		r.generated++
		return []byte("PRIVATE-1"), []byte("pub:PRIVATE-1\n"), nil
	}
	s.Derive = func(priv []byte) ([]byte, error) {
		r.derived++
		return append(append([]byte("pub:"), priv...), '\n'), nil
	}
	s.Prepare = func(pub []byte) error {
		r.prepared++
		r.preparedPub = pub
		_, err := os.Stat(s.Priv)
		r.privAtPrepare = err == nil
		return nil
	}
	return s
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func absent(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s exists (err %v)", p, err)
		}
	}
}

func TestEnsureGeneratesNewPair(t *testing.T) {
	fl := sopstest.NewFlake(t)
	var r recorder
	s := newSpec(t, fl, &r)

	res, err := Ensure(fl.SopsConf, s)
	if err != nil || res != Generated {
		t.Fatalf("Ensure = %v, %v", res, err)
	}
	priv, err := sops.ReadFile(s.Priv)
	if err != nil || string(priv) != "PRIVATE-1" {
		t.Fatalf("private key = %q, %v", priv, err)
	}
	if bytes.Contains(read(t, s.Priv), []byte("PRIVATE-1")) {
		t.Fatal("private key stored in plaintext")
	}
	if got := read(t, s.Pub); string(got) != "pub:PRIVATE-1\n" {
		t.Fatalf("public key = %q", got)
	}
	if r.prepared != 1 || string(r.preparedPub) != "pub:PRIVATE-1\n" || r.privAtPrepare {
		t.Fatalf("Prepare not called once before writing: %+v", r)
	}
}

func TestEnsureExistingPairDoesNothingAndDoesNotDecrypt(t *testing.T) {
	fl := sopstest.NewFlake(t)
	var r recorder
	s := newSpec(t, fl, &r)
	if _, err := Ensure(fl.SopsConf, s); err != nil {
		t.Fatal(err)
	}
	privBefore, pubBefore := read(t, s.Priv), read(t, s.Pub)
	r = recorder{}
	sopstest.UseIdentities(t)

	res, err := Ensure(fl.SopsConf, s)
	if err != nil || res != Existing {
		t.Fatalf("Ensure = %v, %v", res, err)
	}
	if r.generated+r.derived+r.prepared != 0 {
		t.Fatalf("callbacks invoked: %+v", r)
	}
	if !bytes.Equal(privBefore, read(t, s.Priv)) || !bytes.Equal(pubBefore, read(t, s.Pub)) {
		t.Fatal("files modified")
	}
}

func TestEnsureRestoresMissingPublicKeyFromPrivate(t *testing.T) {
	fl := sopstest.NewFlake(t)
	var r recorder
	s := newSpec(t, fl, &r)
	if _, err := Ensure(fl.SopsConf, s); err != nil {
		t.Fatal(err)
	}
	privBefore, pubBefore := read(t, s.Priv), read(t, s.Pub)
	if err := os.Remove(s.Pub); err != nil {
		t.Fatal(err)
	}
	r = recorder{}

	res, err := Ensure(fl.SopsConf, s)
	if err != nil || res != RestoredPublic {
		t.Fatalf("Ensure = %v, %v", res, err)
	}
	if !bytes.Equal(privBefore, read(t, s.Priv)) {
		t.Fatal("private key modified")
	}
	if !bytes.Equal(pubBefore, read(t, s.Pub)) {
		t.Fatalf("restored public key %q differs from original %q", read(t, s.Pub), pubBefore)
	}
	if r.generated != 0 || r.prepared != 0 {
		t.Fatalf("generated or prepared during restore: %+v", r)
	}
}

func TestEnsureRestoreFailsWithoutIdentityAndWritesNothing(t *testing.T) {
	fl := sopstest.NewFlake(t)
	var r recorder
	s := newSpec(t, fl, &r)
	if _, err := Ensure(fl.SopsConf, s); err != nil {
		t.Fatal(err)
	}
	privBefore := read(t, s.Priv)
	if err := os.Remove(s.Pub); err != nil {
		t.Fatal(err)
	}
	sopstest.UseIdentities(t)

	if _, err := Ensure(fl.SopsConf, s); err == nil {
		t.Fatal("expected decrypt failure")
	}
	absent(t, s.Pub)
	if !bytes.Equal(privBefore, read(t, s.Priv)) {
		t.Fatal("private key modified")
	}
}

func TestEnsurePublicWithoutPrivateFails(t *testing.T) {
	fl := sopstest.NewFlake(t)
	var r recorder
	s := newSpec(t, fl, &r)
	if _, err := Ensure(fl.SopsConf, s); err != nil {
		t.Fatal(err)
	}
	pubBefore := read(t, s.Pub)
	if err := os.Remove(s.Priv); err != nil {
		t.Fatal(err)
	}
	r = recorder{}

	if _, err := Ensure(fl.SopsConf, s); err == nil {
		t.Fatal("expected error")
	}
	if r.generated != 0 {
		t.Fatal("generated a new key")
	}
	absent(t, s.Priv)
	if !bytes.Equal(pubBefore, read(t, s.Pub)) {
		t.Fatal("public key modified")
	}
}

func TestEnsureGenerateErrorWritesNothing(t *testing.T) {
	fl := sopstest.NewFlake(t)
	var r recorder
	s := newSpec(t, fl, &r)
	boom := errors.New("boom")
	s.Generate = func() ([]byte, []byte, error) { return nil, nil, boom }

	if _, err := Ensure(fl.SopsConf, s); !errors.Is(err, boom) {
		t.Fatalf("expected generate error, got %v", err)
	}
	absent(t, s.Priv, s.Pub)
	if r.prepared != 0 {
		t.Fatal("Prepare called after failed generation")
	}
}

func TestEnsureRejectsInconsistentGeneratedPair(t *testing.T) {
	fl := sopstest.NewFlake(t)
	var r recorder
	s := newSpec(t, fl, &r)
	s.Generate = func() ([]byte, []byte, error) { return []byte("PRIVATE-1"), []byte("pub:OTHER\n"), nil }

	if _, err := Ensure(fl.SopsConf, s); err == nil {
		t.Fatal("expected mismatch error")
	}
	absent(t, s.Priv, s.Pub)
	if r.prepared != 0 {
		t.Fatal("Prepare called for an inconsistent pair")
	}
}

func TestEnsurePrepareErrorWritesNothing(t *testing.T) {
	fl := sopstest.NewFlake(t)
	var r recorder
	s := newSpec(t, fl, &r)
	boom := errors.New("boom")
	s.Prepare = func([]byte) error { return boom }

	if _, err := Ensure(fl.SopsConf, s); !errors.Is(err, boom) {
		t.Fatalf("expected prepare error, got %v", err)
	}
	absent(t, s.Priv, s.Pub)
}

func TestEnsureEncryptionFailureWritesNothing(t *testing.T) {
	fl := sopstest.NewFlake(t)
	sopstest.WriteConf(t, fl.SopsConf, sopstest.Rule{PathRegex: "^nothing$", Age: []string{fl.Identity.Public}})
	var r recorder
	s := newSpec(t, fl, &r)

	if _, err := Ensure(fl.SopsConf, s); err == nil {
		t.Fatal("expected encryption failure")
	}
	absent(t, s.Priv, s.Pub)
}

func TestEnsureRecoversFromInterruptedGeneration(t *testing.T) {
	fl := sopstest.NewFlake(t)
	var r recorder
	s := newSpec(t, fl, &r)
	if err := os.MkdirAll(filepath.Dir(s.Priv), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := sops.Create(fl.SopsConf, s.Priv, []byte("PRIVATE-1")); err != nil {
		t.Fatal(err)
	}

	res, err := Ensure(fl.SopsConf, s)
	if err != nil || res != RestoredPublic {
		t.Fatalf("Ensure = %v, %v", res, err)
	}
	if got := read(t, s.Pub); string(got) != "pub:PRIVATE-1\n" {
		t.Fatalf("public key = %q", got)
	}
}
