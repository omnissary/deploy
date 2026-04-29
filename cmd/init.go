package cmd

import (
	"os"
	"path/filepath"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
)

func initCmd() *cli.Command {
	return &cli.Command{
		Name:  "init",
		Usage: "initialise SOPS configuration for a new flake",
		Before: func(ctx *cli.Context) error {
			return requireFlake(getConfig(ctx))
		},
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:     "admin-pgp",
				Usage:    "admin PGP fingerprint (repeat for multiple)",
				Required: true,
			},
		},
		Action: func(ctx *cli.Context) error {
			cfg := getConfig(ctx)
			pgpKeys := ctx.StringSlice("admin-pgp")
			if len(pgpKeys) == 0 {
				return errors.New("at least one --admin-pgp fingerprint is required")
			}

			log.Info().Strs("pgp", pgpKeys).Msg("initialising SOPS configuration")

			if err := sops.InitConf(cfg.SopsConf, pgpKeys); err != nil {
				return errors.Wrap(err, "init sops conf")
			}
			log.Info().Str("path", cfg.SopsConf).Msg(".sops.yaml created")

			adminDir := filepath.Join(cfg.FlakeDir, "vars", "admin")
			if err := os.MkdirAll(adminDir, 0o755); err != nil {
				return errors.Wrapf(err, "create %s", adminDir)
			}
			log.Info().Str("path", adminDir).Msg("vars/admin directory created")

			return nil
		},
	}
}
