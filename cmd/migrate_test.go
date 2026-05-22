package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestExtractLegacySharedGroupsResolvesMembers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	conf := filepath.Join(dir, ".sops.yaml")
	raw := []byte(`creation_rules:
  - path_regex: vars/secrets/shared/loki-ca\.yaml$
    key_groups:
      - pgp:
          - ABCD
        age:
          - age1alpha
          - age1bravo
          - age1session
  - path_regex: vars/secrets/shared/dns-zion\.yaml$
    key_groups:
      - age:
          - age1charlie
  - path_regex: vars/secrets/shared/[^/]+\.yaml$
    key_groups:
      - age:
          - age1session
  - path_regex: vars/admin/.+$
    key_groups:
      - pgp:
          - ABCD
`)
	if err := os.WriteFile(conf, raw, 0o644); err != nil {
		t.Fatalf("write conf: %v", err)
	}

	ageToMachine := map[string]string{
		"age1alpha":   "alexandria",
		"age1bravo":   "ares",
		"age1charlie": "pegasus",
	}

	got, err := extractLegacySharedGroups(conf, ageToMachine)
	if err != nil {
		t.Fatalf("extractLegacySharedGroups: %v", err)
	}

	want := map[string][]string{
		"loki-ca":  {"alexandria", "ares"},
		"dns-zion": {"pegasus"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestGroupFromPerGroupRegex(t *testing.T) {
	t.Parallel()

	cases := []struct {
		regex string
		want  string
		ok    bool
	}{
		{`vars/secrets/shared/loki-ca\.yaml$`, "loki-ca", true},
		{`vars/secrets/shared/[^/]+\.yaml$`, "", false},
		{`vars/secrets/[^/]+\.yaml$`, "", false},
		{`vars/admin/.+$`, "", false},
	}
	for _, c := range cases {
		got, ok := groupFromPerGroupRegex(c.regex)
		if got != c.want || ok != c.ok {
			t.Fatalf("groupFromPerGroupRegex(%q) = (%q, %v); want (%q, %v)", c.regex, got, ok, c.want, c.ok)
		}
	}
}

func TestMigrationsCoverTargetVersion(t *testing.T) {
	t.Parallel()

	if len(migrations) == 0 {
		t.Fatal("no migrations defined")
	}
	steps := append([]migration{}, migrations...)
	sort.Slice(steps, func(i, j int) bool { return steps[i].from < steps[j].from })
	want := 0
	for _, m := range steps {
		if m.from != want {
			t.Fatalf("migration from=%d expected %d", m.from, want)
		}
		if m.to != m.from+1 {
			t.Fatalf("migration %d→%d must bump by exactly one", m.from, m.to)
		}
		want = m.to
	}
}
