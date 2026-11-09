package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/nix"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func groupCmd() *cli.Command {
	return &cli.Command{
		Name:  "group",
		Usage: "manage machine groups that share SOPS-encrypted secret files",
		Before: func(ctx *cli.Context) error {
			cfg := getConfig(ctx)
			if err := requireFlake(cfg); err != nil {
				return err
			}
			return requireAdminSOPSConfig(cfg)
		},
		Subcommands: []*cli.Command{
			{
				Name:  "list",
				Usage: "list all declared groups and their members",
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					groups, err := hosts.Groups(cfg.HostsFile)
					if err != nil {
						return err
					}
					names := make([]string, 0, len(groups))
					for name := range groups {
						names = append(names, name)
					}
					sort.Strings(names)
					for _, name := range names {
						fmt.Printf("%s\t%s\n", name, strings.Join(groups[name], ","))
					}
					return nil
				},
			},
			{
				Name:      "show",
				Usage:     "list the members of a group",
				ArgsUsage: "<group>",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					if ctx.NArg() == 0 {
						for _, name := range completionGroupNames(cfg) {
							fmt.Println(name)
						}
					}
				},
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: group show <group>")
					}
					cfg := getConfig(ctx)
					group, err := requireSimpleName("group", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					members, err := hosts.GroupMembers(cfg.HostsFile, group)
					if err != nil {
						return err
					}
					for _, m := range members {
						fmt.Println(m)
					}
					return nil
				},
			},
			{
				Name:      "create",
				Usage:     "create a new group with the listed machines as initial members",
				ArgsUsage: "<group> [machine...]",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					if ctx.NArg() > 0 {
						for _, name := range completionMachineNames(cfg) {
							fmt.Println(name)
						}
					}
				},
				Action: repositoryMutation(func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: group create <group> [machine...]")
					}
					cfg := getConfig(ctx)
					group, err := requireGroupName(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					members, err := validateMembers(cfg, ctx.Args().Slice()[1:])
					if err != nil {
						return err
					}
					if err := hosts.CreateGroup(cfg.HostsFile, group, members); err != nil {
						return err
					}
					log.Info().Str("group", group).Strs("members", members).Msg("group created")
					return syncAllRecipients(cfg)
				}),
			},
			{
				Name:      "add",
				Usage:     "add one or more machines to a group",
				ArgsUsage: "<group> <machine>...",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					switch {
					case ctx.NArg() == 0:
						for _, name := range completionGroupNames(cfg) {
							fmt.Println(name)
						}
					default:
						for _, name := range completionMachineNames(cfg) {
							fmt.Println(name)
						}
					}
				},
				Action: repositoryMutation(func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: group add <group> <machine>...")
					}
					cfg := getConfig(ctx)
					group, err := requireSimpleName("group", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if exists, err := hosts.HasGroup(cfg.HostsFile, group); err != nil {
						return err
					} else if !exists {
						return errors.Errorf("group %q does not exist; run 'group create %s ...' first", group, group)
					}
					members, err := validateMembers(cfg, ctx.Args().Slice()[1:])
					if err != nil {
						return err
					}
					result, err := hosts.AddMembers(cfg.HostsFile, group, members)
					if err != nil {
						return err
					}
					log.Info().Str("group", group).Strs("members", result).Msg("group updated")
					return syncAllRecipients(cfg)
				}),
			},
			{
				Name:      "remove",
				Usage:     "remove one or more machines from a group",
				ArgsUsage: "<group> <machine>...",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					switch {
					case ctx.NArg() == 0:
						for _, name := range completionGroupNames(cfg) {
							fmt.Println(name)
						}
					default:
						members, _ := hosts.GroupMembers(cfg.HostsFile, ctx.Args().Get(0))
						for _, m := range members {
							fmt.Println(m)
						}
					}
				},
				Action: repositoryMutation(func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: group remove <group> <machine>...")
					}
					cfg := getConfig(ctx)
					group, err := requireSimpleName("group", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					result, err := hosts.RemoveMembers(cfg.HostsFile, group, ctx.Args().Slice()[1:])
					if err != nil {
						return err
					}
					log.Info().Str("group", group).Strs("members", result).Msg("group updated")
					return syncAllRecipients(cfg)
				}),
			},
			{
				Name:      "delete",
				Usage:     "delete a group; refuses if the matching shared secrets file still exists",
				ArgsUsage: "<group>",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					if ctx.NArg() == 0 {
						for _, name := range completionGroupNames(cfg) {
							fmt.Println(name)
						}
					}
				},
				Action: repositoryMutation(func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: group delete <group>")
					}
					cfg := getConfig(ctx)
					group, err := requireSimpleName("group", ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if fileExists(vars.SharedSecretsPath(cfg.FlakeDir, group)) {
						return errors.Errorf("shared secrets file for group %q still exists; delete it first with 'secret del'", group)
					}
					if err := hosts.DeleteGroup(cfg.HostsFile, group); err != nil {
						return err
					}
					log.Info().Str("group", group).Msg("group deleted")
					return syncAllRecipients(cfg)
				}),
			},
		},
	}
}

// requireGroupName validates that the group name is well-formed and not already
// in use as a machine name in the flake.
func requireGroupName(cfg *Config, value string) (string, error) {
	name, err := requireSimpleName("group", value)
	if err != nil {
		return "", err
	}
	machines, err := listFlakeMachines(cfg)
	if err != nil {
		return "", err
	}
	for _, m := range machines {
		if m == name {
			return "", errors.Errorf("group name %q collides with a nixosConfigurations machine name", name)
		}
	}
	return name, nil
}

// validateMembers checks each member name is a valid machine in nixosConfigurations.
func validateMembers(cfg *Config, members []string) ([]string, error) {
	if len(members) == 0 {
		return nil, nil
	}
	machines, err := listFlakeMachines(cfg)
	if err != nil {
		return nil, err
	}
	known := make(map[string]struct{}, len(machines))
	for _, m := range machines {
		known[m] = struct{}{}
	}
	out := make([]string, 0, len(members))
	for _, raw := range members {
		name, err := requireMachineName(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := known[name]; !ok {
			return nil, errors.Errorf("machine %q not found in flake nixosConfigurations", name)
		}
		out = append(out, name)
	}
	return out, nil
}

func listFlakeMachines(cfg *Config) ([]string, error) {
	raw, err := nix.EvalApply(cfg.FlakeDir, "nixosConfigurations", "builtins.attrNames")
	if err != nil {
		return nil, errors.Wrap(err, "list machines from flake")
	}
	var machines []string
	if err := json.Unmarshal(raw, &machines); err != nil {
		return nil, errors.Wrap(err, "parse machine list from flake")
	}
	sort.Strings(machines)
	return machines, nil
}
