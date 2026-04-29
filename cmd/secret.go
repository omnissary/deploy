package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
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
					return ensureSecrets(cfg, ctx.Args().Get(0))
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
					machine := ctx.Args().Get(0)
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
					machine := ctx.Args().Get(0)
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
					machine := ctx.Args().Get(0)
					path := secretsPath(cfg, machine)
					log.Info().Str("machine", machine).Str("file", path).Msg("updating secret keys")
					if err := sops.UpdateKeys(cfg.SopsConf, path); err != nil {
						return errors.Wrapf(err, "update keys for %s", machine)
					}
					return nil
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
