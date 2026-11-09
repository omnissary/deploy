package cmd

import (
	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/repolock"
	"github.com/urfave/cli/v2"
	"strings"
)

func protectActions(commands []*cli.Command, prefix string) {
	for _, command := range commands {
		name := strings.TrimSpace(prefix + " " + command.Name)
		protectActions(command.Subcommands, name)
		if len(command.Subcommands) == 0 && (strings.HasPrefix(name, "pki ") || strings.HasPrefix(name, "key yggdrasil ") || name == "machine inspect") {
			before := command.Before
			command.Before = func(ctx *cli.Context) error {
				if before != nil {
					if err := before(ctx); err != nil {
						return err
					}
				}
				for _, arg := range ctx.Args().Slice() {
					if strings.HasPrefix(arg, "--") {
						return errors.New("options must precede positional arguments")
					}
				}
				return nil
			}
		}

		if command.Action == nil || !mutates(name) {
			continue
		}
		action := command.Action
		command.Action = func(ctx *cli.Context) error {
			release, err := repolock.Acquire(getConfig(ctx).FlakeDir)
			if err != nil {
				return err
			}
			defer release()
			return action(ctx)
		}
	}
}
func mutates(name string) bool {
	switch name {
	case "init", "sync", "migrate", "machine init", "machine provision", "machine deploy", "host set":
		return true
	}
	parts := strings.Fields(name)
	if len(parts) < 2 {
		return false
	}
	if parts[0] == "key" || parts[0] == "group" || parts[0] == "secret" || parts[0] == "pki" {
		switch parts[len(parts)-1] {
		case "get", "list", "show", "status", "inspect", "verify", "unlock":
			return false
		}
		return true
	}
	return false
}
