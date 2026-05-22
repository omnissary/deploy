package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

// secretTarget is the resolved target of a secret operation.
type secretTarget struct {
	name string
	path string
	kind targetKind
}

type targetKind int

const (
	targetMachine targetKind = iota
	targetGroup
)

func secretValueFromInput(raw []byte) string {
	return string(raw)
}

func writeSecretValue(w io.Writer, value string) error {
	_, err := io.WriteString(w, value)
	return err
}

func secretCmd() *cli.Command {
	return &cli.Command{
		Name:  "secret",
		Usage: "manage SOPS-encrypted secret files for machines and groups",
		Before: func(ctx *cli.Context) error {
			cfg := getConfig(ctx)
			if err := requireFlake(cfg); err != nil {
				return err
			}
			return requireAdminSOPSConfig(cfg)
		},
		Subcommands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "list top-level secret keys for a target or all secret files",
				ArgsUsage: "[<name>]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "all",
						Usage: "list keys for all secret files",
					},
				},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if ctx.Bool("all") {
						if ctx.NArg() != 0 {
							return errors.New("usage: secret list --all")
						}
						return listAllSecrets(cfg)
					}
					if ctx.NArg() < 1 {
						return errors.New("usage: secret list <name> or secret list --all")
					}
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					return listSecretFileKeys(target.path, target.name)
				},
			},
			{
				Name:      "get",
				Usage:     "decrypt and print the value of a secret key",
				ArgsUsage: "<name> <key>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: secret get <name> <key>")
					}
					cfg := getConfig(ctx)
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					key := ctx.Args().Get(1)
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					log.Debug().Str("target", target.name).Str("key", key).Msg("secret get")
					val, err := sops.DecryptYAMLExtract(target.path, key)
					if err != nil {
						return errors.Wrapf(err, "get secret %s/%s", target.name, key)
					}
					return writeSecretValue(os.Stdout, val)
				},
			},
			{
				Name:      "set",
				Usage:     "read value from stdin and write it as a secret key; creates the file on first use",
				ArgsUsage: "<name> <key>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: secret set <name> <key>")
					}
					cfg := getConfig(ctx)
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if err := ensureSecretFile(cfg, target); err != nil {
						return err
					}
					key := ctx.Args().Get(1)
					log.Debug().Str("target", target.name).Str("key", key).Msg("secret set")
					raw, err := io.ReadAll(os.Stdin)
					if err != nil {
						return errors.Wrap(err, "read stdin")
					}
					if err := sops.SetYAML(target.path, key, secretValueFromInput(raw)); err != nil {
						return errors.Wrapf(err, "set secret %s/%s", target.name, key)
					}
					log.Info().Str("target", target.name).Str("key", key).Msg("secret set")
					return nil
				},
			},
			{
				Name:      "del",
				Usage:     "delete a secret key",
				ArgsUsage: "<name> <key>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: secret del <name> <key>")
					}
					cfg := getConfig(ctx)
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					key := ctx.Args().Get(1)
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					log.Debug().Str("target", target.name).Str("key", key).Msg("secret del")
					if err := sops.DeleteYAML(target.path, key); err != nil {
						return errors.Wrapf(err, "del secret %s/%s", target.name, key)
					}
					log.Info().Str("target", target.name).Str("key", key).Msg("secret deleted")
					return nil
				},
			},
			{
				Name:      "update",
				Usage:     "re-encrypt secrets with the current keys from .sops.yaml",
				ArgsUsage: "[<name>]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "all",
						Usage: "update keys for every encrypted file in the flake",
					},
				},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if ctx.Bool("all") {
						if ctx.NArg() != 0 {
							return errors.New("usage: secret update --all")
						}
						return updateAllSecrets(cfg)
					}
					if ctx.NArg() < 1 {
						return errors.New("usage: secret update <name> or secret update --all")
					}
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					log.Info().Str("file", target.path).Msg("updating secret keys")
					if err := sops.UpdateKeys(cfg.SopsConf, target.path); err != nil {
						return errors.Wrapf(err, "update keys for %s", target.name)
					}
					return nil
				},
			},
			{
				Name:      "verify",
				Usage:     "verify secret integrity/decryption for a target or all encrypted files",
				ArgsUsage: "[<name>]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "fix",
						Usage: "attempt to repair a broken secret file by re-encrypting it with the current .sops.yaml recipients",
					},
				},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if ctx.NArg() < 1 {
						return verifyAllSecrets(cfg, ctx.Bool("fix"))
					}
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					return verifySecretFile(cfg, target.path, ctx.Bool("fix"))
				},
			},
		},
	}
}

// resolveSecretTarget interprets name as either a group declared in the hosts
// file (resolves to the shared secrets file) or a machine declared in the
// flake (resolves to the per-machine secrets file). Groups win when a name
// could match both, but 'group create' rejects collisions to keep the
// namespace clean.
func resolveSecretTarget(cfg *Config, raw string) (*secretTarget, error) {
	name, err := requireSimpleName("name", raw)
	if err != nil {
		return nil, err
	}
	isGroup, err := hosts.HasGroup(cfg.HostsFile, name)
	if err != nil {
		return nil, err
	}
	if isGroup {
		return &secretTarget{
			name: name,
			path: vars.SharedSecretsPath(cfg.FlakeDir, name),
			kind: targetGroup,
		}, nil
	}
	if err := requireMachineInFlake(cfg, name); err != nil {
		return nil, errors.Wrapf(err, "%q is neither a declared group nor a machine", name)
	}
	return &secretTarget{
		name: name,
		path: vars.MachineSecretsPath(cfg.FlakeDir, name),
		kind: targetMachine,
	}, nil
}

// ensureSecretFile creates the encrypted secrets file for the target if it
// does not already exist. For machine targets this also generates the host
// key (so the machine's age recipient is in place); for group targets it
// re-syncs the per-group .sops.yaml rule from the hosts file.
func ensureSecretFile(cfg *Config, target *secretTarget) error {
	switch target.kind {
	case targetMachine:
		if err := ensureHostKey(cfg, target.name); err != nil {
			return errors.Wrapf(err, "ensure host key for %s", target.name)
		}
		return createEncryptedYAMLIfMissing(cfg, target.path, "machine", target.name)
	case targetGroup:
		if err := reconcileGroups(cfg); err != nil {
			return errors.Wrap(err, "reconcile groups before creating shared secret")
		}
		return createEncryptedYAMLIfMissing(cfg, target.path, "group", target.name)
	default:
		return errors.Errorf("unknown target kind %d", target.kind)
	}
}

func createEncryptedYAMLIfMissing(cfg *Config, path, kind, name string) error {
	if _, err := os.Stat(path); err == nil {
		log.Debug().Str(kind, name).Msg("secrets file already exists")
		return nil
	}
	log.Info().Str(kind, name).Str("file", path).Msg("creating secrets file")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Wrapf(err, "create dir for %s", path)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		return errors.Wrapf(err, "write empty secrets for %s", name)
	}
	if err := sops.EncryptYAML(cfg.SopsConf, path); err != nil {
		return errors.Wrapf(err, "encrypt secrets for %s", name)
	}
	return nil
}

func ensureSecrets(cfg *Config, machine string) error {
	if err := ensureHostKey(cfg, machine); err != nil {
		return errors.Wrapf(err, "ensure host key for %s", machine)
	}
	return createEncryptedYAMLIfMissing(cfg, vars.MachineSecretsPath(cfg.FlakeDir, machine), "machine", machine)
}

func verifySecretFile(cfg *Config, path string, fix bool) error {
	log.Info().Str("file", path).Msg("verifying secret")
	if err := sops.VerifyFile(path); err != nil {
		if !fix {
			return err
		}
		log.Warn().Str("file", path).Msg("secret verification failed, attempting repair")
		if repairErr := sops.RepairFile(cfg.SopsConf, path); repairErr != nil {
			return errors.Wrapf(repairErr, "repair secret %s", path)
		}
		if verifyErr := sops.VerifyFile(path); verifyErr != nil {
			return errors.Wrapf(verifyErr, "verify repaired secret %s", path)
		}
		log.Info().Str("file", path).Msg("secret repaired")
		return nil
	}
	log.Info().Str("file", path).Msg("secret verified")
	return nil
}

func verifyAllSecrets(cfg *Config, fix bool) error {
	paths := sops.ListEncryptedFiles(cfg.FlakeDir)
	sort.Strings(paths)
	if len(paths) == 0 {
		log.Info().Msg("no encrypted files found")
		return nil
	}

	for i, path := range paths {
		log.Info().
			Int("index", i+1).
			Int("total", len(paths)).
			Str("file", path).
			Msg("verifying secret")
		if err := sops.VerifyFile(path); err != nil {
			if !fix {
				return err
			}
			log.Warn().
				Int("index", i+1).
				Int("total", len(paths)).
				Str("file", path).
				Msg("secret verification failed, attempting repair")
			if repairErr := sops.RepairFile(cfg.SopsConf, path); repairErr != nil {
				return errors.Wrapf(repairErr, "repair secret %s", path)
			}
			if verifyErr := sops.VerifyFile(path); verifyErr != nil {
				return errors.Wrapf(verifyErr, "verify repaired secret %s", path)
			}
			log.Info().
				Int("index", i+1).
				Int("total", len(paths)).
				Str("file", path).
				Msg("secret repaired")
			continue
		}
		log.Info().
			Int("index", i+1).
			Int("total", len(paths)).
			Str("file", path).
			Msg("secret verified")
	}
	return nil
}

func updateAllSecrets(cfg *Config) error {
	if err := reconcileGroups(cfg); err != nil {
		return err
	}
	paths := sops.ListEncryptedFiles(cfg.FlakeDir)
	sort.Strings(paths)
	if len(paths) == 0 {
		log.Info().Msg("no encrypted files found")
		return nil
	}
	for i, path := range paths {
		log.Info().
			Int("index", i+1).
			Int("total", len(paths)).
			Str("file", path).
			Msg("updating secret keys")
		if err := sops.UpdateKeys(cfg.SopsConf, path); err != nil {
			return errors.Wrapf(err, "update keys for %s", path)
		}
	}
	return nil
}

func listSecretFileKeys(path, label string) error {
	log.Info().Str("file", path).Msg("listing secret keys")
	keys, err := sops.ListYAMLKeys(path)
	if err != nil {
		return err
	}
	for _, key := range keys {
		fmt.Printf("%s\t%s\n", label, key)
	}
	return nil
}

func listAllSecrets(cfg *Config) error {
	var paths []string
	for _, pat := range []string{
		vars.MachineSecretsGlob(cfg.FlakeDir),
		vars.SharedSecretsGlob(cfg.FlakeDir),
	} {
		matches, err := filepath.Glob(pat)
		if err != nil {
			return errors.Wrapf(err, "glob %s", pat)
		}
		paths = append(paths, matches...)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		log.Info().Msg("no secrets found")
		return nil
	}

	for _, path := range paths {
		base := filepath.Base(path)
		name := base[:len(base)-len(".yaml")]
		if err := listSecretFileKeys(path, name); err != nil {
			return err
		}
	}
	return nil
}
