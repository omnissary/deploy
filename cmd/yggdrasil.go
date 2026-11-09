package cmd

import (
	"encoding/json"
	"fmt"
	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
	ygg "git.tatikoma.dev/corpix/deploy/internal/yggdrasil"
	"github.com/urfave/cli/v2"
	"os"
	"path/filepath"
	"time"
)

func yggPublicPath(cfg *Config, machine string) string {
	return vars.PublicResourcePath(cfg.FlakeDir, machine, "yggdrasil.json")
}
func provisionYggdrasil(cfg *Config, machine string, meta manifest.Machine, rotate bool) (ygg.Identity, error) {
	path := vars.MachineSecretsPath(cfg.FlakeDir, machine)
	var identity ygg.Identity
	err := sops.Edit(path, func(file *sops.File) error {
		if file.Has("yggdrasil") {
			existing, err := file.Get("yggdrasil")
			if err != nil {
				return err
			}
			identity, err = ygg.Parse(existing)
			if err != nil {
				return err
			}
			if !rotate {
				return nil
			}
			archive := vars.YggdrasilArchivePath(cfg.FlakeDir, machine, fmt.Sprint(time.Now().UnixNano()))
			if err := os.MkdirAll(filepath.Dir(archive), 0700); err != nil {
				return err
			}
			if err := sops.Create(cfg.SopsConf, archive, []byte(existing)); err != nil {
				return err
			}
		} else if rotate {
			return errors.New("Yggdrasil identity does not exist; use ensure")
		}
		value, err := ygg.Generate()
		if err != nil {
			return err
		}
		identity, err = ygg.Parse(value)
		if err != nil {
			return err
		}
		if rotate {
			file.Set("yggdrasil", value)
		} else {
			if _, err := file.SetIfAbsent("yggdrasil", func() (string, error) { return value, nil }); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return identity, err
	}
	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return identity, err
	}
	output := yggPublicPath(cfg, machine)
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return identity, err
	}
	data = append(data, '\n')
	existing, readErr := os.ReadFile(output)
	if readErr != nil && !os.IsNotExist(readErr) {
		return identity, readErr
	}
	if string(existing) != string(data) {
		if err := atomicfile.Write(output, data, 0644); err != nil {
			return identity, err
		}
	}
	if meta.YggdrasilAddressTag != "" {
		tag := meta.YggdrasilAddressTag
		if tag == "default" {
			tag = ""
		}
		if err := hosts.SetAddress(cfg.HostsFile, machine, tag, identity.Address); err != nil {
			return identity, err
		}
	}
	return identity, nil
}
func yggdrasilCmd() *cli.Command {
	root := &cli.Command{Name: "yggdrasil", Usage: "manage the stored Yggdrasil identity"}
	for _, operation := range []commandOperation{
		{name: "ensure", mutation: true},
		{name: "show", mutation: false},
		{name: "rotate", mutation: true},
	} {
		verb := operation.name
		root.Subcommands = append(root.Subcommands, operationCommand(operation, []cli.Flag{&cli.BoolFlag{Name: "json"}}, func(ctx *cli.Context) error {
			cfg := getConfig(ctx)
			machine, err := requireMachine(cfg, ctx.Args().First())
			if err != nil {
				return err
			}
			var identity ygg.Identity
			if verb == "show" {
				file, err := sops.Open(vars.MachineSecretsPath(cfg.FlakeDir, machine))
				if err != nil {
					return err
				}
				value, err := file.Get("yggdrasil")
				if err != nil {
					return err
				}
				identity, err = ygg.Parse(value)
				if err != nil {
					return err
				}
			} else {
				meta, err := machineMetadata(cfg, machine)
				if err != nil {
					return err
				}
				identity, err = provisionYggdrasil(cfg, machine, meta, verb == "rotate")
				if err != nil {
					return err
				}
			}
			if ctx.Bool("json") {
				return json.NewEncoder(ctx.App.Writer).Encode(identity)
			}
			fmt.Fprintf(ctx.App.Writer, "address: %s\npublic key: %s\n", identity.Address, identity.PublicKey)
			return nil
		}))
	}
	return root
}
