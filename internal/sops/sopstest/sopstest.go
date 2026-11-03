// Package sopstest provides isolated age identities and .sops.yaml fixtures
// for tests that exercise real SOPS encryption.
package sopstest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/agekey"
)

// Identity is an age key pair usable as a SOPS recipient.
type Identity = agekey.Pair

// Rule is a creation rule with age recipients only.
type Rule struct {
	PathRegex string
	Age       []string
}

// NewIdentity generates a fresh age identity.
func NewIdentity(t testing.TB) Identity {
	t.Helper()
	pair, err := agekey.Generate()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	return pair
}

// UseIdentities makes exactly the given identities available for decryption
// for the rest of the test, hiding any key the developer has configured.
// Tests calling it must not run in parallel.
func UseIdentities(t testing.TB, ids ...Identity) {
	t.Helper()
	for _, key := range []string{"SOPS_AGE_KEY_FILE", "SOPS_AGE_KEY_CMD", "SOPS_AGE_SSH_PRIVATE_KEY_FILE", "SOPS_AGE_KEY"} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	if len(ids) == 0 {
		return
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = id.Private
	}
	t.Setenv("SOPS_AGE_KEY", strings.Join(keys, "\n"))
}

// WriteConf writes a .sops.yaml containing the given rules in order.
func WriteConf(t testing.TB, confPath string, rules ...Rule) {
	t.Helper()
	var b strings.Builder
	b.WriteString("creation_rules:\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "  - path_regex: %s\n    key_groups:\n      - age:\n", r.PathRegex)
		for _, a := range r.Age {
			fmt.Fprintf(&b, "          - %s\n", a)
		}
	}
	if err := os.MkdirAll(filepath.Dir(confPath), 0o755); err != nil {
		t.Fatalf("create dir for %s: %v", confPath, err)
	}
	if err := os.WriteFile(confPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write %s: %v", confPath, err)
	}
}

// Flake is a temporary flake directory with a .sops.yaml whose single rule
// encrypts everything to Identity, which is also the only decryption key.
type Flake struct {
	Dir      string
	SopsConf string
	Identity Identity
}

// NewFlake creates a Flake and activates its identity via UseIdentities.
func NewFlake(t testing.TB) Flake {
	t.Helper()
	id := NewIdentity(t)
	UseIdentities(t, id)
	dir := t.TempDir()
	f := Flake{Dir: dir, SopsConf: filepath.Join(dir, ".sops.yaml"), Identity: id}
	WriteConf(t, f.SopsConf, Rule{PathRegex: ".*", Age: []string{id.Public}})
	return f
}
