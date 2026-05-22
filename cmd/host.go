package cmd

import (
	"fmt"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
)

func hostCmd() *cli.Command {
	return &cli.Command{
		Name:  "host",
		Usage: "manage machine->address registry",
		Before: func(ctx *cli.Context) error {
			return requireFlake(getConfig(ctx))
		},
		Subcommands: []*cli.Command{
			{
				Name:      "get",
				Usage:     "print the registered address for a machine",
				ArgsUsage: "<machine>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: host get <machine>")
					}
					cfg := getConfig(ctx)
					machine, err := requireMachine(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					log.Debug().Str("machine", machine).Msg("host get")
					addr, err := hosts.GetAddress(cfg.HostsFile, machine)
					if err != nil {
						return errors.Wrapf(err, "get address for %s", machine)
					}
					fmt.Println(addr)
					return nil
				},
			},
			{
				Name:      "set",
				Usage:     "register an address for a machine",
				ArgsUsage: "<machine> <addr>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: host set <machine> <addr>")
					}
					cfg := getConfig(ctx)
					machine, err := requireMachine(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					addr := ctx.Args().Get(1)
					log.Info().Str("machine", machine).Str("addr", addr).Msg("registering host")
					if err := hosts.SetAddress(cfg.HostsFile, machine, addr); err != nil {
						return errors.Wrapf(err, "set address for %s", machine)
					}
					return nil
				},
			},
		},
	}
}
