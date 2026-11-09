package sops

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
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
	if len(adminPGP) == 0 {
		return errors.New("at least one admin PGP recipient is required")
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
	if err := atomicfile.Create(confPath, out, 0o644); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.Errorf("%s already exists", confPath)
		}
		return err
	}
	return nil
}

// parsePerGroupSharedRegex returns the group name if the given path_regex is a
// per-group shared rule (i.e. vars/secrets/shared/<group>\.yaml$), and false
// for the generic shared fallback rule or anything else.
func parsePerGroupSharedRegex(regex string) (string, bool) {
	if regex == vars.GenericSharedRegex {
		return "", false
	}
	const prefix = "vars/secrets/shared/"
	const suffix = `\.yaml$`
	if !strings.HasPrefix(regex, prefix) || !strings.HasSuffix(regex, suffix) {
		return "", false
	}
	return regex[len(prefix) : len(regex)-len(suffix)], true
}

// ListAdminKeys returns the PGP fingerprints from the generic machine secrets rule.
func ListAdminKeys(confPath string) ([]string, error) {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return nil, err
	}
	group, err := findGenericGroup(cfg, vars.GenericMachineRegex)
	if err != nil {
		return nil, err
	}
	return group.PGP, nil
}

// RequireAdminPGPConfig validates that the mandatory generic rules exist and
// each contains at least one admin PGP recipient.
func RequireAdminPGPConfig(confPath string) error {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return err
	}

	for _, regex := range []string{
		vars.GenericMachineRegex,
		vars.GenericSharedRegex,
		vars.AdminVarsRegex,
	} {
		group, err := findGenericGroup(cfg, regex)
		if err != nil {
			return err
		}
		if len(group.PGP) == 0 {
			return errors.Errorf("sops creation rule %q has no admin PGP recipients; run 'deploy init --admin-pgp ...' first", regex)
		}
	}

	return nil
}

// ListSessionKeys returns the age public keys from the generic machine secrets rule.
func ListSessionKeys(confPath string) ([]string, error) {
	cfg, err := loadSopsYAML(confPath)
	if err != nil {
		return nil, err
	}
	group, err := findGenericGroup(cfg, vars.GenericMachineRegex)
	if err != nil {
		return nil, err
	}
	return group.Age, nil
}

// ListEncryptedFiles returns every encrypted file currently managed in the
// flake. The result is unsorted and may include paths that no longer exist.
func ListEncryptedFiles(flakeDir string) ([]string, error) {
	return allEncryptedFiles(flakeDir)
}

func allEncryptedFiles(flakeDir string) ([]string, error) {
	var files []string
	walkErr := filepath.WalkDir(vars.AdminDir(flakeDir), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			if path == vars.AdminDir(flakeDir) && os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !entry.IsDir() && !strings.HasSuffix(path, ".pub") {
			files = append(files, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
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
	return files, nil
}

func findGenericGroup(cfg sopsYAML, regex string) (keyGroup, error) {
	for _, r := range cfg.CreationRules {
		if r.PathRegex == regex && len(r.KeyGroups) > 0 {
			return r.KeyGroups[0], nil
		}
	}
	return keyGroup{}, errors.Errorf("generic sops creation rule not found: %s", regex)
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
	return atomicfile.Write(confPath, out, 0o644)
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
