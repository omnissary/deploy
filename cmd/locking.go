package cmd

import (
	"strings"

	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/repolock"
)

type commandOperation struct {
	name     string
	mutation bool
}

func operationCommand(operation commandOperation, flags []cli.Flag, action cli.ActionFunc) *cli.Command {
	if operation.mutation {
		action = repositoryMutation(action)
	}
	return &cli.Command{
		Name:   operation.name,
		Flags:  flags,
		Before: optionsBeforeArgs,
		Action: action,
	}
}

func optionsBeforeArgs(ctx *cli.Context) error {
	for _, arg := range ctx.Args().Slice() {
		if strings.HasPrefix(arg, "--") {
			return errors.New("options must precede positional arguments")
		}
	}
	return nil
}

func repositoryMutation(action cli.ActionFunc) cli.ActionFunc {
	return func(ctx *cli.Context) error {
		release, err := repolock.Acquire(getConfig(ctx).FlakeDir)
		if err != nil {
			return err
		}
		defer release()
		return action(ctx)
	}
}
