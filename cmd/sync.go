package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
)

func syncCmd() *cli.Command {
	return &cli.Command{
		Name:  "sync",
		Usage: "regenerate .sops.yaml from admins, session keys, host keys and groups, and re-encrypt files whose recipients are out of date",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "only print what would change; reads no secrets",
			},
		},
		Before: func(ctx *cli.Context) error {
			cfg := getConfig(ctx)
			if err := requireFlake(cfg); err != nil {
				return err
			}
			return requireAdminSOPSConfig(cfg)
		},
		Action: func(ctx *cli.Context) error {
			return runSync(getConfig(ctx), ctx.Bool("dry-run"), os.Stdout)
		},
	}
}

func runSync(cfg *Config, dryRun bool, w io.Writer) error {
	if dryRun {
		m, err := loadRecipientModel(cfg)
		if err != nil {
			return err
		}
		p, err := sops.MakePlan(cfg.SopsConf, cfg.FlakeDir, m)
		if err != nil {
			return err
		}
		printPlan(w, cfg, p)
		return nil
	}
	p, err := syncRecipients(cfg, nil)
	if err != nil {
		return err
	}
	printPlan(w, cfg, p)
	return nil
}

func printPlan(w io.Writer, cfg *Config, p sops.Plan) {
	if p.Empty() {
		fmt.Fprintln(w, "recipients up to date")
		return
	}
	if p.RulesChanged {
		fmt.Fprintf(w, "rules:      %s\n", relToFlake(cfg, cfg.SopsConf))
	}
	for _, path := range p.Rekey {
		fmt.Fprintf(w, "re-encrypt: %s\n", relToFlake(cfg, path))
	}
}

func relToFlake(cfg *Config, path string) string {
	if rel, err := filepath.Rel(cfg.FlakeDir, path); err == nil {
		return rel
	}
	return path
}
