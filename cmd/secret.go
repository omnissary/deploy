package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
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
		Usage: "manage SOPS-encrypted secrets (per-machine and shared groups)",
		Before: func(ctx *cli.Context) error {
			return requireFlake(getConfig(ctx))
		},
		Subcommands: []*cli.Command{
			{
				Name:      "ensure",
				Usage:     "create secrets file; use --machines to create a shared group",
				ArgsUsage: "<name>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "machines",
						Usage: "comma-separated machine list for a shared group secret",
					},
				},
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: secret ensure <name> [--machines m1,m2,...]")
					}
					cfg := getConfig(ctx)
					name := ctx.Args().Get(0)
					if machinesRaw := ctx.String("machines"); machinesRaw != "" {
						group, err := requireSimpleName("group", name)
						if err != nil {
							return err
						}
						machines := splitNames(machinesRaw)
						return ensureSharedSecrets(cfg, group, machines)
					}
					machine, err := requireMachine(cfg, name)
					if err != nil {
						return err
					}
					return ensureSecrets(cfg, machine)
				},
			},
			{
				Name:      "list",
				Usage:     "list top-level secret keys for a name or all secret files",
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
					name := ctx.Args().Get(0)
					path, err := resolveSecretPath(cfg, name)
					if err != nil {
						return err
					}
					return listSecretFileKeys(path, name)
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
					name := ctx.Args().Get(0)
					key := ctx.Args().Get(1)
					path, err := resolveSecretPath(cfg, name)
					if err != nil {
						return err
					}
					log.Debug().Str("name", name).Str("key", key).Msg("secret get")
					val, err := sops.DecryptYAMLExtract(path, key)
					if err != nil {
						return errors.Wrapf(err, "get secret %s/%s", name, key)
					}
					return writeSecretValue(os.Stdout, val)
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
					name := ctx.Args().Get(0)
					key := ctx.Args().Get(1)
					path, err := resolveSecretPath(cfg, name)
					if err != nil {
						return err
					}
					log.Debug().Str("name", name).Str("key", key).Msg("secret del")
					if err := sops.DeleteYAML(path, key); err != nil {
						return errors.Wrapf(err, "del secret %s/%s", name, key)
					}
					log.Info().Str("name", name).Str("key", key).Msg("secret deleted")
					return nil
				},
			},
			{
				Name:      "set",
				Usage:     "read value from stdin and write it as a secret key",
				ArgsUsage: "<name> <key>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: secret set <name> <key>")
					}
					cfg := getConfig(ctx)
					name := ctx.Args().Get(0)
					key := ctx.Args().Get(1)
					path, err := resolveSecretPath(cfg, name)
					if err != nil {
						return err
					}
					log.Debug().Str("name", name).Str("key", key).Msg("secret set")
					raw, err := io.ReadAll(os.Stdin)
					if err != nil {
						return errors.Wrap(err, "read stdin")
					}
					if err := sops.SetYAML(path, key, secretValueFromInput(raw)); err != nil {
						return errors.Wrapf(err, "set secret %s/%s", name, key)
					}
					log.Info().Str("name", name).Str("key", key).Msg("secret set")
					return nil
				},
			},
			{
				Name:      "update",
				Usage:     "re-encrypt secrets with the current keys from .sops.yaml",
				ArgsUsage: "<name>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: secret update <name>")
					}
					cfg := getConfig(ctx)
					name := ctx.Args().Get(0)
					path, err := resolveSecretPath(cfg, name)
					if err != nil {
						return err
					}
					log.Info().Str("name", name).Str("file", path).Msg("updating secret keys")
					if err := sops.UpdateKeys(cfg.SopsConf, path); err != nil {
						return errors.Wrapf(err, "update keys for %s", name)
					}
					return nil
				},
			},
			{
				Name:      "verify",
				Usage:     "verify secret integrity/decryption for a name or all encrypted files",
				ArgsUsage: "[<name>]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "all",
						Usage: "verify all encrypted files managed by the repo",
					},
					&cli.BoolFlag{
						Name:  "fix",
						Usage: "attempt to repair a broken secret file by re-encrypting it with the current .sops.yaml recipients",
					},
				},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if ctx.Bool("all") {
						if ctx.NArg() != 0 {
							return errors.New("usage: secret verify --all")
						}
						return verifyAllSecrets(cfg, ctx.Bool("fix"))
					}
					if ctx.NArg() < 1 {
						return errors.New("usage: secret verify <name> or secret verify --all")
					}
					name := ctx.Args().Get(0)
					path, err := resolveSecretPath(cfg, name)
					if err != nil {
						return err
					}
					return verifySecretFile(cfg, path, ctx.Bool("fix"))
				},
			},
		},
	}
}

// resolveSecretPath finds the secrets file for name, checking the per-machine
// path first and the shared path second. Returns an error if neither exists.
func resolveSecretPath(cfg *Config, name string) (string, error) {
	if p := vars.MachineSecretsPath(cfg.FlakeDir, name); fileExists(p) {
		return p, nil
	}
	if p := vars.SharedSecretsPath(cfg.FlakeDir, name); fileExists(p) {
		return p, nil
	}
	return "", errors.Errorf("no secrets file found for %q; run 'secret ensure %s' first", name, name)
}

// splitNames splits a comma-separated list of names and trims whitespace.
func splitNames(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if name := strings.TrimSpace(part); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func ensureSecrets(cfg *Config, machine string) error {
	if err := ensureHostKey(cfg, machine); err != nil {
		return errors.Wrapf(err, "ensure host key for %s", machine)
	}

	path := vars.MachineSecretsPath(cfg.FlakeDir, machine)
	if _, err := os.Stat(path); err == nil {
		log.Debug().Str("machine", machine).Msg("secrets.yaml already exists")
		return nil
	}

	log.Info().Str("machine", machine).Str("file", path).Msg("creating secrets file")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Wrapf(err, "create machine dir for %s", machine)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		return errors.Wrapf(err, "write empty secrets for %s", machine)
	}
	if err := sops.EncryptYAML(cfg.SopsConf, path); err != nil {
		return errors.Wrapf(err, "encrypt secrets for %s", machine)
	}
	return nil
}

func ensureSharedSecrets(cfg *Config, group string, machines []string) error {
	path := vars.SharedSecretsPath(cfg.FlakeDir, group)

	if _, err := sops.EnsureSharedRule(cfg.SopsConf, cfg.FlakeDir, group, machines, sops.UpdateKeys); err != nil {
		return errors.Wrapf(err, "sync shared sops rule for %s", group)
	}

	if _, err := os.Stat(path); err == nil {
		log.Debug().Str("group", group).Msg("shared secrets.yaml already exists")
		return nil
	}

	log.Info().Str("group", group).Str("file", path).Msg("creating shared secrets file")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Wrapf(err, "create shared dir for %s", group)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		return errors.Wrapf(err, "write empty shared secrets for %s", group)
	}
	if err := sops.EncryptYAML(cfg.SopsConf, path); err != nil {
		return errors.Wrapf(err, "encrypt shared secrets for %s", group)
	}
	return nil
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
