package sops

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/getsops/sops/v3/cmd/sops/formats"

	"git.tatikoma.dev/corpix/deploy/internal/agekey"
)

func setupAgeFlake(t *testing.T) (confPath, secretsPath string) {
	t.Helper()

	pair, err := agekey.Generate()
	if err != nil {
		t.Fatalf("generate age key: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", pair.Private)
	t.Setenv("SOPS_AGE_KEY_FILE", "")

	flakeDir := t.TempDir()
	confPath = filepath.Join(flakeDir, ".sops.yaml")
	conf := fmt.Sprintf("creation_rules:\n  - path_regex: vars/secrets/[^/]+\\.yaml$\n    key_groups:\n      - age:\n          - %s\n", pair.Public)
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatalf("write .sops.yaml: %v", err)
	}

	secretsPath = filepath.Join(flakeDir, "vars", "secrets", "m.yaml")
	if err := os.MkdirAll(filepath.Dir(secretsPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := Create(confPath, secretsPath, []byte("{}\n")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return confPath, secretsPath
}

// decryptRaw mimics `sops -d --extract '["key"]'`, which is what sops-nix
// effectively hands to the machine: the decrypted tree value, untouched.
func decryptRaw(t *testing.T, path, key string) interface{} {
	t.Helper()

	_, tree, _, err := loadDecrypted(path, formats.Yaml)
	if err != nil {
		t.Fatalf("decrypt %s: %v", path, err)
	}
	v, err := tree.Branches[0].Truncate([]interface{}{key})
	if err != nil {
		t.Fatalf("extract %s: %v", key, err)
	}
	return v
}

func randomBytes(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func secretValueCases(t *testing.T) map[string]string {
	return map[string]string{
		"plain":           "hunter2",
		"trailing-nl":     "hunter2\n",
		"multi-line":      "line1\nline2\n",
		"crlf":            "line1\r\nline2\r\n",
		"leading-space":   "  padded",
		"trailing-space":  "padded  ",
		"tab":             "a\tb",
		"yaml-bool":       "yes",
		"yaml-null":       "null",
		"yaml-tilde":      "~",
		"octal-like":      "0123",
		"float-like":      "1e3",
		"hex-like":        "0x10",
		"colon":           "a: b",
		"hash":            "# not a comment",
		"empty":           "",
		"nul-byte":        "a\x00b",
		"random-binary64": randomBytes(t, 64),
		"invalid-utf8":    "\xff\xfe\xfd",
	}
}

func TestSetYAMLThenSecondSetPreservesFirstValue(t *testing.T) {
	for name, value := range secretValueCases(t) {
		t.Run(name, func(t *testing.T) {
			_, path := setupAgeFlake(t)

			if err := SetYAML(path, "rootfs", value); err != nil {
				t.Fatalf("SetYAML rootfs: %v", err)
			}
			if err := SetYAML(path, "other", "second"); err != nil {
				t.Fatalf("SetYAML other: %v", err)
			}

			raw := decryptRaw(t, path, "rootfs")
			if s, ok := raw.(string); !ok || s != value {
				t.Errorf("sops-level value changed: got %T %q, want %q", raw, raw, value)
			}

			got, err := DecryptYAMLExtract(path, "rootfs")
			if err != nil {
				t.Fatalf("DecryptYAMLExtract: %v", err)
			}
			if got != value {
				t.Errorf("DecryptYAMLExtract value changed: got %q, want %q", got, value)
			}
		})
	}
}

// Simulates `secret get` piped into `secret set` (as done by `secret mv` and
// by any manual copy), then checks the value survived.
func TestGetSetRoundTripPreservesValue(t *testing.T) {
	for name, value := range secretValueCases(t) {
		t.Run(name, func(t *testing.T) {
			_, path := setupAgeFlake(t)

			if err := SetYAML(path, "rootfs", value); err != nil {
				t.Fatalf("SetYAML: %v", err)
			}
			got, err := DecryptYAMLExtract(path, "rootfs")
			if err != nil {
				t.Fatalf("DecryptYAMLExtract: %v", err)
			}
			if err := SetYAML(path, "rootfs-copy", got); err != nil {
				t.Fatalf("SetYAML copy: %v", err)
			}
			raw := decryptRaw(t, path, "rootfs-copy")
			if s, ok := raw.(string); !ok || s != value {
				t.Errorf("copied value differs: got %T %q, want %q", raw, raw, value)
			}
		})
	}
}

func TestUpdateKeysPreservesValues(t *testing.T) {
	for name, value := range secretValueCases(t) {
		t.Run(name, func(t *testing.T) {
			conf, path := setupAgeFlake(t)

			if err := SetYAML(path, "rootfs", value); err != nil {
				t.Fatalf("SetYAML: %v", err)
			}
			if err := UpdateKeys(conf, path); err != nil {
				t.Fatalf("UpdateKeys: %v", err)
			}
			raw := decryptRaw(t, path, "rootfs")
			if s, ok := raw.(string); !ok || s != value {
				t.Errorf("value changed after UpdateKeys: got %T %q, want %q", raw, raw, value)
			}
		})
	}
}

func TestEnsureYAMLCreatesMissingKey(t *testing.T) {
	_, path := setupAgeFlake(t)

	created, err := EnsureYAML(path, "rootfs", func() (string, error) { return "generated", nil })
	if err != nil {
		t.Fatalf("EnsureYAML: %v", err)
	}
	if !created {
		t.Fatal("expected EnsureYAML to report creation")
	}
	if got := decryptRaw(t, path, "rootfs"); got != "generated" {
		t.Fatalf("unexpected value %q", got)
	}
}

func TestEnsureYAMLKeepsExistingKey(t *testing.T) {
	_, path := setupAgeFlake(t)

	if err := SetYAML(path, "rootfs", "original"); err != nil {
		t.Fatalf("SetYAML: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	created, err := EnsureYAML(path, "rootfs", func() (string, error) {
		t.Fatal("generate must not be called for an existing key")
		return "", nil
	})
	if err != nil {
		t.Fatalf("EnsureYAML: %v", err)
	}
	if created {
		t.Fatal("expected EnsureYAML to keep the existing key")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("file was rewritten although the key already existed")
	}
}

func TestMissingKeyErrorsWrapErrKeyNotFound(t *testing.T) {
	_, path := setupAgeFlake(t)

	if _, err := DecryptYAMLExtract(path, "absent"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("DecryptYAMLExtract: expected ErrKeyNotFound, got %v", err)
	}
	if err := DeleteYAML(path, "absent"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("DeleteYAML: expected ErrKeyNotFound, got %v", err)
	}
}

func TestDecryptFailureIsNotErrKeyNotFound(t *testing.T) {
	_, path := setupAgeFlake(t)
	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	_, err := DecryptYAMLExtract(path, "absent")
	if err == nil {
		t.Fatal("expected decryption to fail without an identity")
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("decrypt failure must not look like a missing key: %v", err)
	}
}
