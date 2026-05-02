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
)

func secretCmd() *cli.Command {
	return &cli.Command{
		Name:  "secret",
		Usage: "manage per-machine SOPS-encrypted secrets",
		Before: func(ctx *cli.Context) error {
			return requireFlake(getConfig(ctx))
		},
		Subcommands: []*cli.Command{
			{
				Name:      "ensure",
				Usage:     "create machines/<machine>/secrets.yaml if it does not exist",
				ArgsUsage: "<machine>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: secret ensure <machine>")
					}
					cfg := getConfig(ctx)
					machine, err := requireSimpleName("machine", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					return ensureSecrets(cfg, machine)
				},
			},
			{
				Name:      "list",
				Usage:     "list top-level secret keys for one machine or all machine secret files",
				ArgsUsage: "[<machine>]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "all",
						Usage: "list keys for all machine secret files under machines/*/secrets.yaml",
					},
				},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if ctx.Bool("all") {
						if ctx.NArg() != 0 {
							return errors.New("usage: secret list --all")
						}
						return listAllMachineSecrets(cfg)
					}
					if ctx.NArg() < 1 {
						return errors.New("usage: secret list <machine> or secret list --all")
					}
					machine, err := requireSimpleName("machine", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					return listSecretFileKeys(secretsPath(cfg, machine), machine)
				},
			},
			{
				Name:      "get",
				Usage:     "decrypt and print the value of a secret key",
				ArgsUsage: "<machine> <key>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: secret get <machine> <key>")
					}
					cfg := getConfig(ctx)
					machine, err := requireSimpleName("machine", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					key := ctx.Args().Get(1)
					log.Debug().Str("machine", machine).Str("key", key).Msg("secret get")
					path := secretsPath(cfg, machine)
					val, err := sops.DecryptYAMLExtract(path, key)
					if err != nil {
						return errors.Wrapf(err, "get secret %s/%s", machine, key)
					}
					fmt.Print(val)
					if !strings.HasSuffix(val, "\n") {
						fmt.Println()
					}
					return nil
				},
			},
			{
				Name:      "set",
				Usage:     "read value from stdin and write it as a secret key",
				ArgsUsage: "<machine> <key>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: secret set <machine> <key>")
					}
					cfg := getConfig(ctx)
					machine, err := requireSimpleName("machine", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					key := ctx.Args().Get(1)
					log.Debug().Str("machine", machine).Str("key", key).Msg("secret set")

					if err := ensureSecrets(cfg, machine); err != nil {
						return err
					}

					raw, err := io.ReadAll(os.Stdin)
					if err != nil {
						return errors.Wrap(err, "read stdin")
					}
					value := strings.TrimRight(string(raw), "\n")

					path := secretsPath(cfg, machine)
					if err := sops.SetYAML(path, key, value); err != nil {
						return errors.Wrapf(err, "set secret %s/%s", machine, key)
					}
					log.Info().Str("machine", machine).Str("key", key).Msg("secret set")
					return nil
				},
			},
			{
				Name:      "update",
				Usage:     "re-encrypt secrets with the current keys from .sops.yaml",
				ArgsUsage: "<machine>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: secret update <machine>")
					}
					cfg := getConfig(ctx)
					machine, err := requireSimpleName("machine", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					path := secretsPath(cfg, machine)
					log.Info().Str("machine", machine).Str("file", path).Msg("updating secret keys")
					if err := sops.UpdateKeys(cfg.SopsConf, path); err != nil {
						return errors.Wrapf(err, "update keys for %s", machine)
					}
					return nil
				},
			},
			{
				Name:      "verify",
				Usage:     "verify secret integrity/decryption for one machine or all encrypted files",
				ArgsUsage: "[<machine>]",
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
						return errors.New("usage: secret verify <machine> or secret verify --all")
					}
					machine, err := requireSimpleName("machine", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					return verifySecretFile(cfg, secretsPath(cfg, machine), ctx.Bool("fix"))
				},
			},
			{
				Name:  "shared",
				Usage: "manage shared SOPS-encrypted secrets under vars/shared/<group>/secrets.yaml",
				Subcommands: []*cli.Command{
					{
						Name:      "ensure",
						Usage:     "create vars/shared/<group>/secrets.yaml if it does not exist",
						ArgsUsage: "<group>",
						Action: func(ctx *cli.Context) error {
							if ctx.NArg() < 1 {
								return errors.New("usage: secret shared ensure <group>")
							}
							cfg := getConfig(ctx)
							group, err := requireSimpleName("group", ctx.Args().Get(0))
							if err != nil {
								return err
							}
							return ensureSharedSecrets(cfg, group)
						},
					},
					{
						Name:      "list",
						Usage:     "list top-level shared secret keys",
						ArgsUsage: "<group>",
						Action: func(ctx *cli.Context) error {
							if ctx.NArg() < 1 {
								return errors.New("usage: secret shared list <group>")
							}
							cfg := getConfig(ctx)
							group, err := requireSimpleName("group", ctx.Args().Get(0))
							if err != nil {
								return err
							}
							return listSecretFileKeys(sharedSecretsPath(cfg, group), group)
						},
					},
					{
						Name:      "get",
						Usage:     "decrypt and print the value of a shared secret key",
						ArgsUsage: "<group> <key>",
						Action: func(ctx *cli.Context) error {
							if ctx.NArg() < 2 {
								return errors.New("usage: secret shared get <group> <key>")
							}
							cfg := getConfig(ctx)
							group, err := requireSimpleName("group", ctx.Args().Get(0))
							if err != nil {
								return err
							}
							key := ctx.Args().Get(1)
							log.Debug().Str("group", group).Str("key", key).Msg("shared secret get")
							path := sharedSecretsPath(cfg, group)
							val, err := sops.DecryptYAMLExtract(path, key)
							if err != nil {
								return errors.Wrapf(err, "get shared secret %s/%s", group, key)
							}
							fmt.Print(val)
							if !strings.HasSuffix(val, "\n") {
								fmt.Println()
							}
							return nil
						},
					},
					{
						Name:      "set",
						Usage:     "read value from stdin and write it as a shared secret key",
						ArgsUsage: "<group> <key>",
						Action: func(ctx *cli.Context) error {
							if ctx.NArg() < 2 {
								return errors.New("usage: secret shared set <group> <key>")
							}
							cfg := getConfig(ctx)
							group, err := requireSimpleName("group", ctx.Args().Get(0))
							if err != nil {
								return err
							}
							key := ctx.Args().Get(1)
							log.Debug().Str("group", group).Str("key", key).Msg("shared secret set")

							if err := ensureSharedSecrets(cfg, group); err != nil {
								return err
							}

							raw, err := io.ReadAll(os.Stdin)
							if err != nil {
								return errors.Wrap(err, "read stdin")
							}
							value := strings.TrimRight(string(raw), "\n")

							path := sharedSecretsPath(cfg, group)
							if err := sops.SetYAML(path, key, value); err != nil {
								return errors.Wrapf(err, "set shared secret %s/%s", group, key)
							}
							log.Info().Str("group", group).Str("key", key).Msg("shared secret set")
							return nil
						},
					},
					{
						Name:      "update",
						Usage:     "re-encrypt shared secrets with the current keys from .sops.yaml",
						ArgsUsage: "<group>",
						Action: func(ctx *cli.Context) error {
							if ctx.NArg() < 1 {
								return errors.New("usage: secret shared update <group>")
							}
							cfg := getConfig(ctx)
							group, err := requireSimpleName("group", ctx.Args().Get(0))
							if err != nil {
								return err
							}
							path := sharedSecretsPath(cfg, group)
							if _, err := sops.UpsertSharedRule(cfg.SopsConf, cfg.FlakeDir, cfg.SharedGroupsFile, group, sops.UpdateKeys); err != nil {
								return errors.Wrapf(err, "sync shared keys for %s", group)
							}
							log.Info().Str("group", group).Str("file", path).Msg("updating shared secret keys")
							if err := sops.UpdateKeys(cfg.SopsConf, path); err != nil {
								return errors.Wrapf(err, "update keys for shared group %s", group)
							}
							return nil
						},
					},
					{
						Name:      "verify",
						Usage:     "verify shared secret integrity/decryption",
						ArgsUsage: "<group>",
						Flags: []cli.Flag{
							&cli.BoolFlag{
								Name:  "fix",
								Usage: "attempt to repair a broken shared secret file by re-encrypting it with the current .sops.yaml recipients",
							},
						},
						Action: func(ctx *cli.Context) error {
							if ctx.NArg() < 1 {
								return errors.New("usage: secret shared verify <group>")
							}
							cfg := getConfig(ctx)
							group, err := requireSimpleName("group", ctx.Args().Get(0))
							if err != nil {
								return err
							}
							return verifySecretFile(cfg, sharedSecretsPath(cfg, group), ctx.Bool("fix"))
						},
					},
				},
			},
		},
	}
}

func secretsPath(cfg *Config, machine string) string {
	return filepath.Join(cfg.FlakeDir, "machines", machine, "secrets.yaml")
}

func ensureSecrets(cfg *Config, machine string) error {
	path := secretsPath(cfg, machine)
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

func sharedSecretsPath(cfg *Config, group string) string {
	return filepath.Join(cfg.FlakeDir, "vars", "shared", group, "secrets.yaml")
}

func ensureSharedSecrets(cfg *Config, group string) error {
	path := sharedSecretsPath(cfg, group)

	if _, err := sops.UpsertSharedRule(cfg.SopsConf, cfg.FlakeDir, cfg.SharedGroupsFile, group, sops.UpdateKeys); err != nil {
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

func listAllMachineSecrets(cfg *Config) error {
	paths, err := filepath.Glob(filepath.Join(cfg.FlakeDir, "machines", "*", "secrets.yaml"))
	if err != nil {
		return errors.Wrap(err, "glob machine secrets")
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		log.Info().Msg("no machine secrets found")
		return nil
	}

	for _, path := range paths {
		machine := filepath.Base(filepath.Dir(path))
		if err := listSecretFileKeys(path, machine); err != nil {
			return err
		}
	}
	return nil
}
