// Package sopsrules manages per-machine creation rules in .sops.yaml.
package sopsrules

import (
	"bytes"
	"os"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"gopkg.in/yaml.v3"
)

// sopsYAML mirrors the top-level structure of a .sops.yaml file.
type sopsYAML struct {
	Keys          []string       `yaml:"keys,omitempty"`
	CreationRules []creationRule `yaml:"creation_rules"`
}

type creationRule struct {
	PathRegex  string     `yaml:"path_regex"`
	KeyGroups  []keyGroup `yaml:"key_groups,omitempty"`
	// flat style (no key_groups): kept for round-trip
	PGP        string     `yaml:"pgp,omitempty"`
	Age        string     `yaml:"age,omitempty"`
}

type keyGroup struct {
	PGP []string `yaml:"pgp,omitempty"`
	Age []string `yaml:"age,omitempty"`
}

// UpsertMachineRules ensures that machine-specific creation rules exist in
// confPath for the given machine + age key, derived from the generic fallback
// rule. It also runs UpdateKeys on any existing encrypted files.
//
// Returns true if the .sops.yaml file was modified.
func UpsertMachineRules(confPath, machine, ageKey string, updateFn func(confPath, filePath string) error) (bool, error) {
	log.Debug().Str("machine", machine).Str("age", ageKey).Msg("upsert sops rules")

	raw, err := os.ReadFile(confPath)
	if err != nil {
		return false, errors.Wrapf(err, "read %s", confPath)
	}

	var cfg sopsYAML
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return false, errors.Wrapf(err, "parse %s", confPath)
	}

	machineRegex := `machines/` + machine + `/secrets\.yaml$`
	varsRegex := `vars/per-machine/` + machine + `/.+$`
	genericRegex := `machines/[^/]+/secrets\.yaml$`

	// Find PGP keys from the generic fallback rule.
	var pgpKeys []string
	for _, r := range cfg.CreationRules {
		if r.PathRegex == genericRegex {
			if len(r.KeyGroups) > 0 {
				pgpKeys = r.KeyGroups[0].PGP
			}
			break
		}
	}
	if len(pgpKeys) == 0 {
		return false, errors.Errorf("generic sops creation rule not found: %s", genericRegex)
	}

	wantedGroup := keyGroup{PGP: pgpKeys, Age: []string{ageKey}}

	// Check if the machine rules already match.
	machineIdx, varsIdx := -1, -1
	for i, r := range cfg.CreationRules {
		switch r.PathRegex {
		case machineRegex:
			machineIdx = i
		case varsRegex:
			varsIdx = i
		}
	}

	machineRule := creationRule{PathRegex: machineRegex, KeyGroups: []keyGroup{wantedGroup}}
	varsRule := creationRule{PathRegex: varsRegex, KeyGroups: []keyGroup{wantedGroup}}

	changed := false
	switch {
	case machineIdx == -1:
		cfg.CreationRules = prependRules(cfg.CreationRules, machineRule, genericRegex)
		changed = true
	case !rulesEqual(cfg.CreationRules[machineIdx], machineRule):
		cfg.CreationRules[machineIdx] = machineRule
		changed = true
	}
	switch {
	case varsIdx == -1:
		cfg.CreationRules = prependRules(cfg.CreationRules, varsRule, genericRegex)
		changed = true
	case !rulesEqual(cfg.CreationRules[varsIdx], varsRule):
		cfg.CreationRules[varsIdx] = varsRule
		changed = true
	}

	if changed {
		out, err := marshalSopsYAML(cfg)
		if err != nil {
			return false, err
		}
		tmp := confPath + ".tmp"
		if err := os.WriteFile(tmp, out, 0o644); err != nil {
			return false, errors.Wrapf(err, "write tmp %s", tmp)
		}
		if err := os.Rename(tmp, confPath); err != nil {
			_ = os.Remove(tmp)
			return false, errors.Wrapf(err, "rename %s", confPath)
		}
		log.Info().Str("machine", machine).Msg("updated .sops.yaml")
	}

	if changed {
		for _, path := range existingFiles(machine) {
			if _, err := os.Stat(path); err != nil {
				continue
			}
			log.Debug().Str("file", path).Msg("sops updatekeys")
			if err := updateFn(confPath, path); err != nil {
				return changed, errors.Wrapf(err, "updatekeys %s", path)
			}
		}
	}

	return changed, nil
}

func existingFiles(machine string) []string {
	return []string{
		"machines/" + machine + "/secrets.yaml",
		"vars/per-machine/" + machine + "/openssh/ssh_host_ed25519_key",
		"vars/per-machine/" + machine + "/initrd-ssh/id_ed25519",
	}
}

func prependRules(rules []creationRule, r creationRule, beforeRegex string) []creationRule {
	idx := -1
	for i, existing := range rules {
		if existing.PathRegex == beforeRegex {
			idx = i
			break
		}
	}
	if idx == -1 {
		return append([]creationRule{r}, rules...)
	}
	out := make([]creationRule, 0, len(rules)+1)
	out = append(out, rules[:idx]...)
	out = append(out, r)
	out = append(out, rules[idx:]...)
	return out
}

func rulesEqual(a, b creationRule) bool {
	if a.PathRegex != b.PathRegex {
		return false
	}
	if len(a.KeyGroups) != len(b.KeyGroups) {
		return false
	}
	for i := range a.KeyGroups {
		if !stringSliceEqual(a.KeyGroups[i].PGP, b.KeyGroups[i].PGP) {
			return false
		}
		if !stringSliceEqual(a.KeyGroups[i].Age, b.KeyGroups[i].Age) {
			return false
		}
	}
	return true
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func marshalSopsYAML(cfg sopsYAML) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, errors.Wrap(err, "marshal sops yaml")
	}
	return buf.Bytes(), nil
}
