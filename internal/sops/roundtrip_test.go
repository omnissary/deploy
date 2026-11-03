package sops

import (
	"crypto/rand"
	"path/filepath"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
)

func setupAgeFlake(t *testing.T) (confPath, secretsPath string) {
	t.Helper()
	fl := sopstest.NewFlake(t)
	secretsPath = filepath.Join(fl.Dir, "m.yaml")
	if err := Create(fl.SopsConf, secretsPath, []byte("{}\n")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return fl.SopsConf, secretsPath
}

// decryptRaw mimics `sops -d --extract '["key"]'`, which is what sops-nix
// effectively hands to the machine: the decrypted tree value, untouched.
func decryptRaw(t *testing.T, path, key string) interface{} {
	t.Helper()

	f := mustOpen(t, path)
	v, err := f.tree.Branches[0].Truncate([]interface{}{key})
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

func setKey(t *testing.T, path, key, value string) {
	t.Helper()
	if err := Edit(path, func(f *File) error { f.Set(key, value); return nil }); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
}

func TestSecondSetPreservesFirstValue(t *testing.T) {
	for name, value := range secretValueCases(t) {
		t.Run(name, func(t *testing.T) {
			_, path := setupAgeFlake(t)

			setKey(t, path, "rootfs", value)
			setKey(t, path, "other", "second")

			raw := decryptRaw(t, path, "rootfs")
			if s, ok := raw.(string); !ok || s != value {
				t.Errorf("sops-level value changed: got %T %q, want %q", raw, raw, value)
			}
			if got := mustGet(t, path, "rootfs"); got != value {
				t.Errorf("Get value changed: got %q, want %q", got, value)
			}
		})
	}
}

// Simulates `secret get` piped into `secret set`, then checks the value
// survived.
func TestGetSetRoundTripPreservesValue(t *testing.T) {
	for name, value := range secretValueCases(t) {
		t.Run(name, func(t *testing.T) {
			_, path := setupAgeFlake(t)

			setKey(t, path, "rootfs", value)
			setKey(t, path, "rootfs-copy", mustGet(t, path, "rootfs"))

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

			setKey(t, path, "rootfs", value)
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
