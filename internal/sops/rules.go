package sops

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"git.tatikoma.dev/corpix/deploy/internal/sshkey"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
	"gopkg.in/yaml.v3"
)

type sopsYAML struct {
	CreationRules []creationRule `yaml:"creation_rules"`
}

type creationRule struct {
	PathRegex string     `yaml:"path_regex"`
	KeyGroups []keyGroup `yaml:"key_groups,omitempty"`
	PGP       string     `yaml:"pgp,omitempty"`
	Age       string     `yaml:"age,omitempty"`
}

type keyGroup struct {
	PGP []string `yaml:"pgp,omitempty"`
	Age []string `yaml:"age,omitempty"`
}

// InitConf creates a fresh .sops.yaml with the generic machine secrets rule,
// generic shared secrets rule, and admin-only vars/admin rule.
// Fails if the file already exists.
func InitConf(confPath string, adminPGP []string) error {
	if _, err := os.Stat(confPath); err == nil {
		return errors.Errorf("%s already exists", confPath)
	}
	cfg := sopsYAML{
		CreationRules: []creationRule{
			{
				PathRegex: vars.GenericMachineRegex,
				KeyGroups: []keyGroup{{PGP: adminPGP}},
			},
			{
				PathRegex: vars.GenericSharedRegex,
				KeyGroups: []keyGroup{{PGP: adminPGP}},
			},
			{
				PathRegex: vars.AdminVarsRegex,
				KeyGroups: []keyGroup{{PGP: adminPGP}},
			},
		},
	}
	out, err := marshalSopsYAML(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(confPath, out, 0o644)
}

// UpsertMachineRules ensures machine-specific creation rules exist in confPath.
// Machine rules inherit the full key group from the generic rule (PGP + session
// age keys) and append the host age key on top.
// Returns true if .sops.yaml was modified.
func UpsertMachineRules(confPath, flakeDir, machine, ageKey string, updateFn func(confPath, filePath string) error) (bool, error) {
	log.Debug().Str("machine", machine).Str("age", ageKey).Msg("upsert sops rules")

	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return false, err
	}

	machineRegex := vars.MachineSecretsRegex(machine)
	varsRegex := vars.MachineVarsRegex(machine)

	var genericGroup keyGroup
	found := false
	for _, r := range cfg.CreationRules {
		if r.PathRegex == vars.GenericMachineRegex && len(r.KeyGroups) > 0 {
			genericGroup = r.KeyGroups[0]
			found = true
			break
		}
	}
	if !found {
		return false, errors.Errorf("generic sops creation rule not found: %s", vars.GenericMachineRegex)
	}
	if len(genericGroup.PGP) == 0 && len(genericGroup.Age) == 0 {
		log.Warn().Str("machine", machine).Msg("no admin keys in generic sops rule; secrets will only be readable by the machine — add admin keys with 'deploy key add --pgp'")
	}

	wantedGroup := keyGroup{
		PGP: genericGroup.PGP,
		Age: append(append([]string{}, genericGroup.Age...), ageKey),
	}

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
		cfg.CreationRules = prependBefore(cfg.CreationRules, machineRule, vars.GenericMachineRegex)
		changed = true
	case !rulesEqual(cfg.CreationRules[machineIdx], machineRule):
		cfg.CreationRules[machineIdx] = machineRule
		changed = true
	}
	if idx := indexOfRule(cfg.CreationRules, machineRegex); idx != -1 && idx > indexOfRule(cfg.CreationRules, vars.GenericMachineRegex) {
		cfg.CreationRules = moveRuleBefore(cfg.CreationRules, machineRegex, vars.GenericMachineRegex)
		changed = true
	}
	switch {
	case varsIdx == -1:
		cfg.CreationRules = prependBeforeAny(cfg.CreationRules, varsRule, vars.GenericInitrdRegex, vars.GenericHostKeyRegex, vars.GenericMachineRegex)
		changed = true
	case !rulesEqual(cfg.CreationRules[varsIdx], varsRule):
		cfg.CreationRules[varsIdx] = varsRule
		changed = true
	}
	if idx := indexOfRule(cfg.CreationRules, varsRegex); idx != -1 {
		anchor := firstRuleIndex(cfg.CreationRules, vars.GenericInitrdRegex, vars.GenericHostKeyRegex, vars.GenericMachineRegex)
		if anchor != -1 && idx > anchor {
			cfg.CreationRules = moveRuleBeforeAny(cfg.CreationRules, varsRegex, vars.GenericInitrdRegex, vars.GenericHostKeyRegex, vars.GenericMachineRegex)
			changed = true
		}
	}

	if changed {
		if err := writeSopsYAML(confPath, cfg); err != nil {
			return false, err
		}
		log.Info().Str("machine", machine).Msg("updated .sops.yaml")

		for _, path := range vars.MachineFiles(flakeDir, machine) {
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

// EnsureSharedRule creates or updates the .sops.yaml creation rule for the
// shared secrets group, setting the recipients to the given machines.
// Returns true if .sops.yaml was modified.
func EnsureSharedRule(confPath, flakeDir, group string, machines []string, updateFn func(confPath, filePath string) error) (bool, error) {
	log.Debug().Str("group", group).Strs("machines", machines).Msg("ensure shared sops rule")

	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return false, err
	}

	genericGroup, err := findGenericGroup(cfg, vars.GenericSharedRegex)
	if err != nil {
		return false, err
	}

	ages, err := machineAgeKeys(flakeDir, machines)
	if err != nil {
		return false, errors.Wrapf(err, "derive age keys for shared group %s", group)
	}

	wantedGroup := keyGroup{
		PGP: append([]string{}, genericGroup.PGP...),
		Age: uniqueStrings(append(append([]string{}, genericGroup.Age...), ages...)),
	}

	groupRegex := vars.SharedSecretsRegex(group)
	groupRule := creationRule{PathRegex: groupRegex, KeyGroups: []keyGroup{wantedGroup}}

	idx := indexOfRule(cfg.CreationRules, groupRegex)
	changed := false
	switch {
	case idx == -1:
		cfg.CreationRules = prependBefore(cfg.CreationRules, groupRule, vars.GenericSharedRegex)
		changed = true
	case !rulesEqual(cfg.CreationRules[idx], groupRule):
		cfg.CreationRules[idx] = groupRule
		changed = true
	}

	if changed {
		if err := writeSopsYAML(confPath, cfg); err != nil {
			return false, err
		}
		log.Info().Str("group", group).Msg("updated shared rule in .sops.yaml")

		path := vars.SharedSecretsPath(flakeDir, group)
		if _, err := os.Stat(path); err == nil {
			log.Debug().Str("file", path).Msg("sops updatekeys")
			if err := updateFn(confPath, path); err != nil {
				return changed, errors.Wrapf(err, "updatekeys %s", path)
			}
		}
	}

	return changed, nil
}

// AddMachineToSharedGroup adds a machine's age key to an existing shared group
// rule. Returns true if .sops.yaml was modified. No-op if already present.
func AddMachineToSharedGroup(confPath, flakeDir, group, machineAgeKey string, updateFn func(confPath, filePath string) error) (bool, error) {
	log.Debug().Str("group", group).Str("age", machineAgeKey).Msg("add machine to shared group")

	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return false, err
	}

	groupRegex := vars.SharedSecretsRegex(group)
	idx := indexOfRule(cfg.CreationRules, groupRegex)
	if idx == -1 {
		return false, errors.Errorf("shared group rule %q not found in .sops.yaml; run 'secret ensure %s --machines ...' first", group, group)
	}

	if len(cfg.CreationRules[idx].KeyGroups) == 0 {
		return false, errors.Errorf("shared group rule %q has no key groups", group)
	}
	kg := cfg.CreationRules[idx].KeyGroups[0]
	if containsStr(kg.Age, machineAgeKey) {
		return false, nil
	}

	cfg.CreationRules[idx].KeyGroups[0].Age = uniqueStrings(append(kg.Age, machineAgeKey))
	if err := writeSopsYAML(confPath, cfg); err != nil {
		return false, err
	}
	log.Info().Str("group", group).Msg("enrolled machine in shared group in .sops.yaml")

	path := vars.SharedSecretsPath(flakeDir, group)
	if _, err := os.Stat(path); err == nil {
		log.Debug().Str("file", path).Msg("sops updatekeys")
		if err := updateFn(confPath, path); err != nil {
			return true, errors.Wrapf(err, "updatekeys %s", path)
		}
	}
	return true, nil
}

// ListAdminKeys returns the PGP fingerprints from the generic machine secrets rule.
func ListAdminKeys(confPath string) ([]string, error) {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return nil, err
	}
	for _, r := range cfg.CreationRules {
		if r.PathRegex == vars.GenericMachineRegex && len(r.KeyGroups) > 0 {
			return r.KeyGroups[0].PGP, nil
		}
	}
	return nil, nil
}

// AddAdminKey adds a PGP fingerprint to every creation rule and re-encrypts all
// existing encrypted files. Returns true if anything changed.
func AddAdminKey(confPath, flakeDir, fingerprint string, updateFn func(string, string) error) (bool, error) {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return false, err
	}

	changed := false
	for i, r := range cfg.CreationRules {
		for j, kg := range r.KeyGroups {
			if !containsStr(kg.PGP, fingerprint) {
				cfg.CreationRules[i].KeyGroups[j].PGP = append(kg.PGP, fingerprint)
				changed = true
			}
		}
	}
	if !changed {
		return false, nil
	}

	if err := writeSopsYAML(confPath, cfg); err != nil {
		return false, err
	}
	log.Info().Str("fingerprint", fingerprint).Msg("added admin PGP key")
	return true, updateAllFiles(confPath, flakeDir, updateFn)
}

// RemoveAdminKey removes a PGP fingerprint from every creation rule and
// re-encrypts all existing encrypted files. Returns true if anything changed.
func RemoveAdminKey(confPath, flakeDir, fingerprint string, updateFn func(string, string) error) (bool, error) {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return false, err
	}

	changed := false
	for i, r := range cfg.CreationRules {
		for j, kg := range r.KeyGroups {
			filtered := removeStr(kg.PGP, fingerprint)
			if len(filtered) != len(kg.PGP) {
				cfg.CreationRules[i].KeyGroups[j].PGP = filtered
				changed = true
			}
		}
	}
	if !changed {
		return false, nil
	}

	if err := writeSopsYAML(confPath, cfg); err != nil {
		return false, err
	}
	log.Info().Str("fingerprint", fingerprint).Msg("removed admin PGP key")
	return true, updateAllFiles(confPath, flakeDir, updateFn)
}

// ListSessionKeys returns the age public keys from the generic machine secrets rule.
func ListSessionKeys(confPath string) ([]string, error) {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return nil, err
	}
	for _, r := range cfg.CreationRules {
		if r.PathRegex == vars.GenericMachineRegex && len(r.KeyGroups) > 0 {
			return r.KeyGroups[0].Age, nil
		}
	}
	return nil, nil
}

// AddSessionKey adds an age public key to every creation rule that has an
// explicit key group. This makes a session key transparently usable anywhere
// an admin key already has access.
// Returns true if anything changed.
func AddSessionKey(confPath, flakeDir, ageKey string, updateFn func(string, string) error) (bool, error) {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return false, err
	}

	changed := false
	for i, r := range cfg.CreationRules {
		if !sessionEligible(r) {
			continue
		}
		for j, kg := range r.KeyGroups {
			if !containsStr(kg.Age, ageKey) {
				cfg.CreationRules[i].KeyGroups[j].Age = append(kg.Age, ageKey)
				changed = true
			}
		}
	}
	if !changed {
		return false, nil
	}

	if err := writeSopsYAML(confPath, cfg); err != nil {
		return false, err
	}
	log.Info().Str("age", ageKey).Msg("added session age key")
	return true, updateAllFiles(confPath, flakeDir, updateFn)
}

// RemoveSessionKey removes an age public key from all creation rules and
// re-encrypts affected files. Returns true if anything changed.
func RemoveSessionKey(confPath, flakeDir, ageKey string, updateFn func(string, string) error) (bool, error) {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return false, err
	}

	changed := false
	for i, r := range cfg.CreationRules {
		for j, kg := range r.KeyGroups {
			filtered := removeStr(kg.Age, ageKey)
			if len(filtered) != len(kg.Age) {
				cfg.CreationRules[i].KeyGroups[j].Age = filtered
				changed = true
			}
		}
	}
	if !changed {
		return false, nil
	}

	if err := writeSopsYAML(confPath, cfg); err != nil {
		return false, err
	}
	log.Info().Str("age", ageKey).Msg("removed session age key")
	return true, updateAllFiles(confPath, flakeDir, updateFn)
}

// sessionEligible reports whether a rule should receive session age keys.
// Rules with empty key groups (bootstrap state) are eligible so that a
// freshly-created .sops.yaml immediately gains a usable recipient.
func sessionEligible(r creationRule) bool {
	return len(r.KeyGroups) > 0
}

// ListEncryptedFiles returns every encrypted file currently managed in the
// flake. The result is unsorted and may include paths that no longer exist.
func ListEncryptedFiles(flakeDir string) []string {
	return allEncryptedFiles(flakeDir)
}

func allEncryptedFiles(flakeDir string) []string {
	var files []string
	adminGlob, _ := filepath.Glob(vars.AdminGlob(flakeDir))
	for _, f := range adminGlob {
		if !strings.HasSuffix(f, ".pub") {
			fi, err := os.Stat(f)
			if err == nil && !fi.IsDir() {
				files = append(files, f)
			}
		}
	}
	for _, pat := range []string{
		vars.MachineSecretsGlob(flakeDir),
		vars.SharedSecretsGlob(flakeDir),
		vars.MachineHostKeyGlob(flakeDir),
		vars.MachineInitrdKeyGlob(flakeDir),
	} {
		matches, _ := filepath.Glob(pat)
		files = append(files, matches...)
	}
	return files
}

func findGenericGroup(cfg sopsYAML, regex string) (keyGroup, error) {
	for _, r := range cfg.CreationRules {
		if r.PathRegex == regex && len(r.KeyGroups) > 0 {
			return r.KeyGroups[0], nil
		}
	}
	return keyGroup{}, errors.Errorf("generic sops creation rule not found: %s", regex)
}

func machineAgeKeys(flakeDir string, machines []string) ([]string, error) {
	keys := make([]string, 0, len(machines))
	for _, machine := range machines {
		pubPath := vars.MachineHostKeyPubPath(flakeDir, machine)
		pub, err := os.ReadFile(pubPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, errors.Wrapf(err, "read host public key for %s", machine)
		}
		age, err := sshkey.ToAge(pub)
		if err != nil {
			return nil, errors.Wrapf(err, "derive age key for %s", machine)
		}
		keys = append(keys, age)
	}
	return uniqueStrings(keys), nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func updateAllFiles(confPath, flakeDir string, updateFn func(string, string) error) error {
	files := make([]string, 0)
	for _, path := range allEncryptedFiles(flakeDir) {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		files = append(files, path)
	}

	total := len(files)
	for i, path := range files {
		log.Info().
			Int("index", i+1).
			Int("total", total).
			Str("file", path).
			Msg("re-encrypting secret with updated recipients")
		if err := updateFn(confPath, path); err != nil {
			return errors.Wrapf(err, "updatekeys %s", path)
		}
		log.Info().
			Int("index", i+1).
			Int("total", total).
			Str("file", path).
			Msg("re-encrypted secret")
	}
	return nil
}

func prependBefore(rules []creationRule, r creationRule, beforeRegex string) []creationRule {
	return prependBeforeAny(rules, r, beforeRegex)
}

func prependBeforeAny(rules []creationRule, r creationRule, beforeRegexes ...string) []creationRule {
	idx := firstRuleIndex(rules, beforeRegexes...)
	if idx == -1 {
		return append([]creationRule{r}, rules...)
	}
	out := make([]creationRule, 0, len(rules)+1)
	out = append(out, rules[:idx]...)
	out = append(out, r)
	out = append(out, rules[idx:]...)
	return out
}

func moveRuleBefore(rules []creationRule, pathRegex, beforeRegex string) []creationRule {
	return moveRuleBeforeAny(rules, pathRegex, beforeRegex)
}

func moveRuleBeforeAny(rules []creationRule, pathRegex string, beforeRegexes ...string) []creationRule {
	src := indexOfRule(rules, pathRegex)
	if src == -1 {
		return rules
	}
	rule := rules[src]
	remaining := append(append([]creationRule{}, rules[:src]...), rules[src+1:]...)
	return prependBeforeAny(remaining, rule, beforeRegexes...)
}

func firstRuleIndex(rules []creationRule, regexes ...string) int {
	idx := -1
	for _, regex := range regexes {
		for i, existing := range rules {
			if existing.PathRegex == regex && (idx == -1 || i < idx) {
				idx = i
			}
		}
	}
	return idx
}

func indexOfRule(rules []creationRule, regex string) int {
	for i, rule := range rules {
		if rule.PathRegex == regex {
			return i
		}
	}
	return -1
}

func rulesEqual(a, b creationRule) bool {
	if a.PathRegex != b.PathRegex || len(a.KeyGroups) != len(b.KeyGroups) {
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

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func removeStr(ss []string, s string) []string {
	out := ss[:0:0]
	for _, v := range ss {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

func loadSopsYAML(confPath string) (sopsYAML, error) {
	raw, err := os.ReadFile(confPath)
	if err != nil {
		return sopsYAML{}, errors.Wrapf(err, "read %s", confPath)
	}
	var cfg sopsYAML
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return sopsYAML{}, errors.Wrapf(err, "parse %s", confPath)
	}
	return cfg, nil
}

func writeSopsYAML(confPath string, cfg sopsYAML) error {
	out, err := marshalSopsYAML(cfg)
	if err != nil {
		return err
	}
	tmp := confPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return errors.Wrapf(err, "write tmp %s", tmp)
	}
	if err := os.Rename(tmp, confPath); err != nil {
		_ = os.Remove(tmp)
		return errors.Wrapf(err, "rename %s", confPath)
	}
	return nil
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
