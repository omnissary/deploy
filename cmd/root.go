package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"git.tatikoma.dev/corpix/deploy/internal/nix"
	"github.com/urfave/cli/v2"
)

// Config holds values derived from global flags and is threaded through commands
// via cli.Context metadata.
type Config struct {
	// FlakeDir is the absolute path to the flake root.
	FlakeDir string
	// SopsConf is the absolute path to .sops.yaml.
	SopsConf string
	// HostsFile is the absolute path to the hosts YAML registry.
	HostsFile string
	// KnownHosts is the path to the local known_hosts file.
	KnownHosts string
	// SSHUser is the remote user for SSH connections.
	SSHUser string
	// ImagesFlake is the flake ref for the deploy-images repository.
	ImagesFlake string
	// System is the target NixOS system tuple (e.g. x86_64-linux).
	System string
}

// nixSystem returns the NixOS system tuple for the current machine's architecture.
func nixSystem() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64-linux"
	case "arm64":
		return "aarch64-linux"
	default:
		return runtime.GOARCH + "-linux"
	}
}

func defaultNixBuildCores() int {
	cores := runtime.NumCPU() / 2
	if cores < 1 {
		return 1
	}
	return cores
}

const configKey = "deploy.config"

var simpleNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

func getConfig(ctx *cli.Context) *Config {
	return ctx.App.Metadata[configKey].(*Config)
}

func requireSimpleName(kind, value string) (string, error) {
	if value == "" {
		return "", errors.Errorf("%s name is required", kind)
	}
	if !simpleNamePattern.MatchString(value) {
		return "", errors.Errorf("invalid %s name %q: allowed characters are lowercase letters, digits, underscore, and hyphen", kind, value)
	}
	return value, nil
}

// requireFlake validates that the flake root contains flake.nix.
// Commands that interact with the flake should call this at the start.
func requireFlake(cfg *Config) error {
	if _, err := os.Stat(filepath.Join(cfg.FlakeDir, "flake.nix")); err != nil {
		return errors.Errorf("no flake.nix found in %s (use --flake to set the path)", cfg.FlakeDir)
	}
	return nil
}

func requireMachineInFlake(cfg *Config, machine string) error {
	raw, err := nix.EvalApply(cfg.FlakeDir, "nixosConfigurations", "builtins.attrNames")
	if err != nil {
		return errors.Wrapf(err, "list machines from flake")
	}
	var machines []string
	if err := json.Unmarshal(raw, &machines); err != nil {
		return errors.Wrapf(err, "parse machine list from flake")
	}
	for _, m := range machines {
		if m == machine {
			return nil
		}
	}
	slices.Sort(machines)
	return errors.Errorf("machine %q not found in flake nixosConfigurations (available: %s)",
		machine, strings.Join(machines, ", "))
}

func requireMachine(cfg *Config, value string) (string, error) {
	machine, err := requireSimpleName("machine", value)
	if err != nil {
		return "", err
	}
	if err := requireFlake(cfg); err != nil {
		return "", err
	}
	if err := requireMachineInFlake(cfg, machine); err != nil {
		return "", err
	}
	return machine, nil
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
			&cli.StringFlag{
				Name:    "images-flake",
				Usage:   "flake ref for the deploy-images repository",
				Value:   "git+https://git.tatikoma.dev/corpix/deploy-images",
				EnvVars: []string{"DEPLOY_IMAGES_FLAKE"},
			},
			&cli.StringFlag{
				Name:    "system",
				Usage:   "target NixOS system tuple (e.g. x86_64-linux, aarch64-linux)",
				Value:   nixSystem(),
				EnvVars: []string{"DEPLOY_SYSTEM"},
			},
			&cli.IntFlag{
				Name:    "nix-build-cores",
				Usage:   "number of build cores to expose to nix builds",
				Value:   defaultNixBuildCores(),
				EnvVars: []string{"DEPLOY_NIX_BUILD_CORES"},
			},
			&cli.IntFlag{
				Name:    "nix-max-jobs",
				Usage:   "maximum number of concurrent nix build jobs",
				Value:   1,
				EnvVars: []string{"DEPLOY_NIX_MAX_JOBS"},
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

			nix.SetWriters(writerConfig{}.stdout(), writerConfig{}.stderr())
			nix.SetConfig(
				strconv.Itoa(ctx.Int("nix-build-cores")),
				strconv.Itoa(ctx.Int("nix-max-jobs")),
			)

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
				FlakeDir:    abs,
				SopsConf:    filepath.Join(abs, ".sops.yaml"),
				HostsFile:   resolve(ctx.Path("hosts-file")),
				KnownHosts:  resolve(ctx.Path("known-hosts")),
				SSHUser:     ctx.String("ssh-user"),
				ImagesFlake: ctx.String("images-flake"),
				System:      ctx.String("system"),
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
