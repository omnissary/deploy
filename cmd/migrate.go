package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/sshkey"
	"git.tatikoma.dev/corpix/deploy/internal/state"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

// migration is a single schema-version step. Every step is idempotent: rerunning
// it on already-migrated state must be a no-op.
type migration struct {
	from, to int
	name     string
	apply    func(*Config) error
}

// migrations are applied in order, each one expected to bump the schema by one.
// Each new step appends to this slice and increments state.TargetVersion.
var migrations = []migration{
	{from: 0, to: 1, name: "extract groups from .sops.yaml per-group shared rules", apply: migrateV0toV1},
}

func migrateCmd() *cli.Command {
	return &cli.Command{
		Name:  "migrate",
		Usage: "bring vars/.deploy.state forward, reconcile groups, then re-encrypt and verify all secrets",
		Before: func(ctx *cli.Context) error {
			cfg := getConfig(ctx)
			if err := requireFlake(cfg); err != nil {
				return err
			}
			return requireAdminSOPSConfig(cfg)
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "check",
				Usage: "report current and target schema versions without changing anything",
			},
		},
		Action: func(ctx *cli.Context) error {
			cfg := getConfig(ctx)
			current, err := state.Load(cfg.FlakeDir)
			if err != nil {
				return err
			}
			if ctx.Bool("check") {
				fmt.Printf("current: %d\ntarget:  %d\n", current.Version, state.TargetVersion)
				return nil
			}
			return runMigrations(cfg, current.Version)
		},
	}
}

// runMigrations applies pending schema migrations in order, then runs the
// always-on housekeeping pass (reconcile groups, re-encrypt all secrets,
// verify all secrets). Safe to run repeatedly.
func runMigrations(cfg *Config, currentVersion int) error {
	if currentVersion > state.TargetVersion {
		return errors.Errorf("state version %d is newer than this binary supports (target %d); upgrade deploy",
			currentVersion, state.TargetVersion)
	}
	for _, m := range migrations {
		if m.from < currentVersion {
			continue
		}
		if m.from != currentVersion {
			return errors.Errorf("missing migration step %d→%d", currentVersion, currentVersion+1)
		}
		log.Info().Int("from", m.from).Int("to", m.to).Str("name", m.name).Msg("running migration")
		if err := m.apply(cfg); err != nil {
			return errors.Wrapf(err, "migration %d→%d", m.from, m.to)
		}
		if err := state.Save(cfg.FlakeDir, &state.State{Version: m.to}); err != nil {
			return errors.Wrap(err, "persist state after migration")
		}
		currentVersion = m.to
	}
	if currentVersion != state.TargetVersion {
		if err := state.Save(cfg.FlakeDir, &state.State{Version: state.TargetVersion}); err != nil {
			return errors.Wrap(err, "persist state")
		}
		currentVersion = state.TargetVersion
	}
	log.Info().Int("version", currentVersion).Msg("schema migrations complete")

	if err := reconcileGroups(cfg); err != nil {
		return errors.Wrap(err, "reconcile groups")
	}
	if err := updateAllSecrets(cfg); err != nil {
		return errors.Wrap(err, "update all secrets")
	}
	if err := verifyAllSecrets(cfg); err != nil {
		return errors.Wrap(err, "secret verify")
	}
	log.Info().Msg("migrate complete")
	return nil
}

// migrateV0toV1 imports group membership from the legacy per-group shared
// rules in .sops.yaml into the hosts file. The follow-up reconcile pass
// rewrites those rules from the hosts file as their new source of truth.
// Idempotent: existing hosts groups are left alone.
func migrateV0toV1(cfg *Config) error {
	ageToMachine, err := loadMachineAgeKeys(cfg.FlakeDir)
	if err != nil {
		return err
	}

	groupsFound, err := extractLegacySharedGroups(cfg.SopsConf, ageToMachine)
	if err != nil {
		return err
	}
	if len(groupsFound) == 0 {
		log.Info().Msg("no per-group shared rules found in .sops.yaml; nothing to import")
		return nil
	}

	existing, err := hosts.Groups(cfg.HostsFile)
	if err != nil {
		return errors.Wrap(err, "load existing groups")
	}

	names := make([]string, 0, len(groupsFound))
	for name := range groupsFound {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		members := groupsFound[name]
		if _, ok := existing[name]; ok {
			log.Info().Str("group", name).Msg("group already declared in hosts file; skipping import")
			continue
		}
		if err := hosts.CreateGroup(cfg.HostsFile, name, members); err != nil {
			return errors.Wrapf(err, "import group %s", name)
		}
		log.Info().Str("group", name).Strs("members", members).Msg("imported group from .sops.yaml")
	}
	return nil
}

// extractLegacySharedGroups parses .sops.yaml looking for per-group rules
// (path_regex of the form vars/secrets/shared/<name>\.yaml$) and returns a
// map of group name → declared machine members. Non-machine age recipients
// (sessions) are ignored — they're inherited via the generic shared rule.
func extractLegacySharedGroups(confPath string, ageToMachine map[string]string) (map[string][]string, error) {
	raw, err := os.ReadFile(confPath)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", confPath)
	}
	var doc struct {
		CreationRules []struct {
			PathRegex string `yaml:"path_regex"`
			KeyGroups []struct {
				Age []string `yaml:"age"`
			} `yaml:"key_groups"`
		} `yaml:"creation_rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, errors.Wrapf(err, "parse %s", confPath)
	}

	out := map[string][]string{}
	for _, r := range doc.CreationRules {
		name, ok := groupFromPerGroupRegex(r.PathRegex)
		if !ok {
			continue
		}
		seen := map[string]struct{}{}
		members := make([]string, 0)
		for _, kg := range r.KeyGroups {
			for _, age := range kg.Age {
				machine, known := ageToMachine[age]
				if !known {
					continue
				}
				if _, dup := seen[machine]; dup {
					continue
				}
				seen[machine] = struct{}{}
				members = append(members, machine)
			}
		}
		sort.Strings(members)
		out[name] = members
	}
	return out, nil
}

// groupFromPerGroupRegex extracts the group name from a path_regex of the
// form vars/secrets/shared/<name>\.yaml$, skipping the generic shared
// fallback rule.
func groupFromPerGroupRegex(regex string) (string, bool) {
	const prefix = "vars/secrets/shared/"
	const suffix = `\.yaml$`
	if !strings.HasPrefix(regex, prefix) || !strings.HasSuffix(regex, suffix) {
		return "", false
	}
	inner := regex[len(prefix) : len(regex)-len(suffix)]
	if inner == "[^/]+" {
		return "", false
	}
	return inner, true
}

// loadMachineAgeKeys reads every committed host pubkey under vars/secrets/*
// and returns a map of derived age public key → machine name.
func loadMachineAgeKeys(flakeDir string) (map[string]string, error) {
	pattern := vars.MachineHostKeyGlob(flakeDir) + ".pub"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, errors.Wrapf(err, "glob %s", pattern)
	}
	out := make(map[string]string, len(matches))
	for _, path := range matches {
		rel, err := filepath.Rel(flakeDir, path)
		if err != nil {
			return nil, errors.Wrapf(err, "rel %s", path)
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		// Expected layout: vars/secrets/<machine>/openssh/ssh_host_ed25519_key.pub
		if len(parts) < 5 {
			continue
		}
		machine := parts[2]
		pub, err := os.ReadFile(path)
		if err != nil {
			return nil, errors.Wrapf(err, "read %s", path)
		}
		age, err := sshkey.ToAge(pub)
		if err != nil {
			return nil, errors.Wrapf(err, "derive age key for %s", machine)
		}
		out[age] = machine
	}
	return out, nil
}
