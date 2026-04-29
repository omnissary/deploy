package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"
)

// Config holds values derived from global flags and is threaded through commands
// via cli.Context metadata.
type Config struct {
	// FlakeDir is the absolute path to the flake root.
	FlakeDir string
	// SopsConf is the absolute path to .sops.yaml.
	SopsConf string
	// HostsFile is the absolute path to the hosts JSON registry.
	HostsFile string
	// KnownHosts is the path to the local known_hosts file.
	KnownHosts string
	// SSHUser is the remote user for SSH connections.
	SSHUser string
}

const configKey = "deploy.config"

func getConfig(ctx *cli.Context) *Config {
	return ctx.App.Metadata[configKey].(*Config)
}

// requireFlake validates that the flake root contains flake.nix.
// Commands that interact with the flake should call this at the start.
func requireFlake(cfg *Config) error {
	if _, err := os.Stat(filepath.Join(cfg.FlakeDir, "flake.nix")); err != nil {
		return errors.Errorf("no flake.nix found in %s (use --flake to set the path)", cfg.FlakeDir)
	}
	return nil
}

// SSHArgs returns the common SSH option flags derived from Config.
func (c *Config) SSHArgs() []string {
	return []string{
		"-o", "UserKnownHostsFile=" + c.KnownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UpdateHostKeys=no",
	}
}

// SSHTarget returns "user@host".
func (c *Config) SSHTarget(host string) string {
	return c.SSHUser + "@" + host
}

// NixFlakeRef returns the flake reference prefix.
func (c *Config) NixFlakeRef() string {
	return c.FlakeDir
}

// MachineAttr returns the nix attribute path for a machine's nixosConfiguration.
func (c *Config) MachineAttr(machine, suffix string) string {
	return "nixosConfigurations." + machine + "." + suffix
}

func New() *cli.App {
	app := &cli.App{
		Name:  "deploy",
		Usage: "NixOS machine management tool",
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:    "flake",
				Aliases: []string{"f"},
				Usage:   "path to the flake root",
				Value:   ".",
				EnvVars: []string{"DEPLOY_FLAKE"},
			},
			&cli.StringFlag{
				Name:    "ssh-user",
				Usage:   "SSH user for remote operations",
				Value:   "root",
				EnvVars: []string{"DEPLOY_SSH_USER"},
			},
			&cli.PathFlag{
				Name:    "known-hosts",
				Usage:   "path to local known_hosts file",
				Value:   "known_hosts",
				EnvVars: []string{"DEPLOY_KNOWN_HOSTS"},
			},
			&cli.PathFlag{
				Name:    "hosts-file",
				Usage:   "path to the machine->host JSON registry",
				Value:   "hosts",
				EnvVars: []string{"DEPLOY_HOSTS_FILE"},
			},
			&cli.BoolFlag{
				Name:    "debug",
				Aliases: []string{"d"},
				Usage:   "enable debug logging",
				EnvVars: []string{"DEPLOY_DEBUG"},
			},
		},
		Before: func(ctx *cli.Context) error {
			if ctx.Bool("debug") {
				log.SetLevel(log.DebugLevel)
			} else {
				log.SetLevel(log.InfoLevel)
			}

			flake := ctx.Path("flake")
			abs, err := filepath.Abs(flake)
			if err != nil {
				return errors.Wrapf(err, "resolve flake path %q", flake)
			}

			resolve := func(p string) string {
				if filepath.IsAbs(p) {
					return p
				}
				return filepath.Join(abs, p)
			}

			cfg := &Config{
				FlakeDir:   abs,
				SopsConf:   filepath.Join(abs, ".sops.yaml"),
				HostsFile:  resolve(ctx.Path("hosts-file")),
				KnownHosts: resolve(ctx.Path("known-hosts")),
				SSHUser:    ctx.String("ssh-user"),
			}
			ctx.App.Metadata = map[string]interface{}{configKey: cfg}

			log.Debug().
				Str("flake", cfg.FlakeDir).
				Str("ssh_user", cfg.SSHUser).
				Str("known_hosts", cfg.KnownHosts).
				Str("hosts_file", cfg.HostsFile).
				Msg("deploy config")
			return nil
		},
		Commands: []*cli.Command{
			initCmd(),
			hostCmd(),
			keyCmd(),
			secretCmd(),
			machineCmd(),
			kexecCmd(),
		},
		ExitErrHandler: func(ctx *cli.Context, err error) {
			if err != nil {
				// Trim cli internal exit error noise for user-facing messages.
				msg := err.Error()
				if strings.HasPrefix(msg, "exit status") {
					os.Exit(1)
				}
				log.Error().Err(err).Msg("fatal")
				os.Exit(1)
			}
		},
	}
	return app
}
