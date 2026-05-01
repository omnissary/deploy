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
	"gopkg.in/yaml.v3"
)

const (
	genericMachineRegex = `machines/[^/]+/secrets\.yaml$`
	genericSharedRegex  = `vars/shared/[^/]+/secrets\.yaml$`
	adminVarsRegex      = `vars/admin/.+$`
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

type sharedGroup struct {
	Machines []string `yaml:"machines"`
}

// InitConf creates a fresh .sops.yaml with the generic machine secrets rule
// and the admin-only vars/admin rule. Fails if the file already exists.
func InitConf(confPath string, adminPGP []string) error {
	if _, err := os.Stat(confPath); err == nil {
		return errors.Errorf("%s already exists", confPath)
	}
	cfg := sopsYAML{
		CreationRules: []creationRule{
			{
				PathRegex: genericMachineRegex,
				KeyGroups: []keyGroup{{PGP: adminPGP}},
			},
			{
				PathRegex: adminVarsRegex,
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
func UpsertMachineRules(confPath, machine, ageKey string, updateFn func(confPath, filePath string) error) (bool, error) {
	log.Debug().Str("machine", machine).Str("age", ageKey).Msg("upsert sops rules")

	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return false, err
	}

	machineRegex := `machines/` + machine + `/secrets\.yaml$`
	varsRegex := `vars/per-machine/` + machine + `/.+$`

	var genericGroup keyGroup
	found := false
	for _, r := range cfg.CreationRules {
		if r.PathRegex == genericMachineRegex && len(r.KeyGroups) > 0 {
			genericGroup = r.KeyGroups[0]
			found = true
			break
		}
	}
	if !found {
		return false, errors.Errorf("generic sops creation rule not found: %s", genericMachineRegex)
	}
	if len(genericGroup.PGP) == 0 {
		return false, errors.Errorf("generic sops rule has no PGP keys")
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
		cfg.CreationRules = prependBefore(cfg.CreationRules, machineRule, genericMachineRegex)
		changed = true
	case !rulesEqual(cfg.CreationRules[machineIdx], machineRule):
		cfg.CreationRules[machineIdx] = machineRule
		changed = true
	}
	switch {
	case varsIdx == -1:
		cfg.CreationRules = prependBefore(cfg.CreationRules, varsRule, genericMachineRegex)
		changed = true
	case !rulesEqual(cfg.CreationRules[varsIdx], varsRule):
		cfg.CreationRules[varsIdx] = varsRule
		changed = true
	}

	if changed {
		if err := writeSopsYAML(confPath, cfg); err != nil {
			return false, err
		}
		log.Info().Str("machine", machine).Msg("updated .sops.yaml")

		for _, path := range machineFiles(machine) {
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

// UpsertAllSharedRules ensures every shared secret group rule matches
// vars/shared/groups.yaml. Returns true if .sops.yaml was modified.
func UpsertAllSharedRules(confPath, flakeDir, groupsPath string, updateFn func(confPath, filePath string) error) (bool, error) {
	groups, err := loadSharedGroups(groupsPath)
	if err != nil {
		return false, err
	}
	if len(groups) == 0 {
		return false, nil
	}

	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)

	changed := false
	for _, name := range names {
		groupChanged, err := UpsertSharedRule(confPath, flakeDir, groupsPath, name, updateFn)
		if err != nil {
			return changed, err
		}
		changed = changed || groupChanged
	}
	return changed, nil
}

// UpsertSharedRule ensures a shared secret creation rule exists for one group.
// The rule inherits the generic shared-secret key group and appends every
// machine age recipient listed in vars/shared/groups.yaml.
func UpsertSharedRule(confPath, flakeDir, groupsPath, group string, updateFn func(confPath, filePath string) error) (bool, error) {
	log.Debug().Str("group", group).Msg("upsert shared sops rule")

	groups, err := loadSharedGroups(groupsPath)
	if err != nil {
		return false, err
	}
	entry, ok := groups[group]
	if !ok {
		return false, errors.Errorf("shared group %q not found in %s", group, groupsPath)
	}

	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return false, err
	}

	genericGroup, err := findGenericGroup(cfg, genericSharedRegex)
	if err != nil {
		return false, err
	}

	ages, err := machineAgeKeys(flakeDir, entry.Machines)
	if err != nil {
		return false, errors.Wrapf(err, "derive age keys for shared group %s", group)
	}

	wantedGroup := keyGroup{
		PGP: append([]string{}, genericGroup.PGP...),
		Age: uniqueStrings(append(append([]string{}, genericGroup.Age...), ages...)),
	}

	groupRegex := `vars/shared/` + group + `/secrets\.yaml$`
	groupRule := creationRule{PathRegex: groupRegex, KeyGroups: []keyGroup{wantedGroup}}

	idx := -1
	for i, r := range cfg.CreationRules {
		if r.PathRegex == groupRegex {
			idx = i
			break
		}
	}

	changed := false
	switch {
	case idx == -1:
		cfg.CreationRules = prependBefore(cfg.CreationRules, groupRule, genericSharedRegex)
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

		path := filepath.Join(flakeDir, "vars", "shared", group, "secrets.yaml")
		if _, err := os.Stat(path); err == nil {
			log.Debug().Str("file", path).Msg("sops updatekeys")
			if err := updateFn(confPath, path); err != nil {
				return changed, errors.Wrapf(err, "updatekeys %s", path)
			}
		}
	}

	return changed, nil
}

// ListAdminKeys returns the PGP fingerprints from the generic machine secrets rule.
func ListAdminKeys(confPath string) ([]string, error) {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return nil, err
	}
	for _, r := range cfg.CreationRules {
		if r.PathRegex == genericMachineRegex && len(r.KeyGroups) > 0 {
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
		if r.PathRegex == genericMachineRegex && len(r.KeyGroups) > 0 {
			return r.KeyGroups[0].Age, nil
		}
	}
	return nil, nil
}

// AddSessionKey adds an age public key to creation rules eligible for session
// access (generic machine rule + rules that already have age recipients).
// Admin-only rules (vars/admin, initrd-ssh, openssh) are skipped.
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
func sessionEligible(r creationRule) bool {
	if r.PathRegex == adminVarsRegex {
		return false
	}
	if r.PathRegex == genericSharedRegex {
		return true
	}
	if strings.Contains(r.PathRegex, "initrd-ssh") || strings.Contains(r.PathRegex, "openssh") {
		return false
	}
	if r.PathRegex == genericMachineRegex {
		return true
	}
	for _, kg := range r.KeyGroups {
		if len(kg.Age) > 0 {
			return true
		}
	}
	return false
}

func machineFiles(machine string) []string {
	return []string{
		"machines/" + machine + "/secrets.yaml",
		"vars/per-machine/" + machine + "/openssh/ssh_host_ed25519_key",
		"vars/per-machine/" + machine + "/initrd-ssh/id_ed25519",
	}
}

func allEncryptedFiles(flakeDir string) []string {
	var files []string
	adminGlob, _ := filepath.Glob(filepath.Join(flakeDir, "vars", "admin", "*"))
	for _, f := range adminGlob {
		if !strings.HasSuffix(f, ".pub") {
			fi, err := os.Stat(f)
			if err == nil && !fi.IsDir() {
				files = append(files, f)
			}
		}
	}
	for _, pat := range []string{
		filepath.Join(flakeDir, "machines", "*", "secrets.yaml"),
		filepath.Join(flakeDir, "vars", "shared", "*", "secrets.yaml"),
		filepath.Join(flakeDir, "vars", "per-machine", "*", "openssh", "ssh_host_ed25519_key"),
		filepath.Join(flakeDir, "vars", "per-machine", "*", "initrd-ssh", "id_ed25519"),
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

func loadSharedGroups(groupsPath string) (map[string]sharedGroup, error) {
	if _, err := os.Stat(groupsPath); err != nil {
		if os.IsNotExist(err) {
			return map[string]sharedGroup{}, nil
		}
		return nil, errors.Wrapf(err, "stat %s", groupsPath)
	}

	raw, err := os.ReadFile(groupsPath)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", groupsPath)
	}

	var groups map[string]sharedGroup
	if err := yaml.Unmarshal(raw, &groups); err != nil {
		return nil, errors.Wrapf(err, "parse %s", groupsPath)
	}
	if groups == nil {
		groups = map[string]sharedGroup{}
	}
	return groups, nil
}

func machineAgeKeys(flakeDir string, machines []string) ([]string, error) {
	keys := make([]string, 0, len(machines))
	for _, machine := range machines {
		pubPath := filepath.Join(flakeDir, "vars", "per-machine", machine, "openssh", "ssh_host_ed25519_key.pub")
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
	for _, path := range allEncryptedFiles(flakeDir) {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		log.Debug().Str("file", path).Msg("sops updatekeys")
		if err := updateFn(confPath, path); err != nil {
			return errors.Wrapf(err, "updatekeys %s", path)
		}
	}
	return nil
}

func prependBefore(rules []creationRule, r creationRule, beforeRegex string) []creationRule {
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
