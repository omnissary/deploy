package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/nix"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
	"github.com/urfave/cli/v2"
)

// Config holds values derived from global flags and is threaded through commands
// via cli.Context metadata.
type Config struct {
	machineInfo func(string) (manifest.Machine, error)
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
	System         string
	SystemExplicit bool
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

// urfave/cli emits top-level fish completions behind a generated
// __fish_<app>_no_subcommand helper. In our environment that helper does not
// match the root "deploy <TAB>" case correctly, so fish falls back to generic
// file completion and hides the actual subcommand list. Nested completions
// still work because they use __fish_seen_subcommand_from, so the bug is
// limited to the root command state.
//
// Keep the workaround local to deploy rather than carrying a vendor patch:
// rewrite only the generated top-level completion guards to fish's builtin
// __fish_use_subcommand helper, which is designed for "offer subcommands until
// a non-flag argument is present" and behaves correctly on current fish.
// The rewrite covers both forms urfave/cli emits at the root level:
//   - flag entries:    complete -c ...
//   - command entries: complete -r -c ...
//
// fishScopedCmd describes a command whose subcommand-level fish completions need
// scoping: file suppression, static-condition patching, and dynamic argument stanzas.
type fishScopedCmd struct {
	Parent      string
	Subcommands []string
}

// fishScopedCmds is the single source of truth driving all fish completion patches
// and dynamic stanza generation. Extend this slice when new top-level commands with
// subcommands are added.
var fishScopedCmds = []fishScopedCmd{
	{Parent: "secret", Subcommands: []string{"list", "get", "set", "del", "update", "mv", "verify"}},
	{Parent: "key", Subcommands: []string{"host", "initrd", "ensure", "admin", "session"}},
	{Parent: "machine", Subcommands: []string{"init", "inspect", "provision", "build", "eval", "audit", "deploy", "ssh", "unlock"}},
	{Parent: "group", Subcommands: []string{"list", "show", "create", "add", "remove", "delete"}},
	{Parent: "host", Subcommands: []string{"get", "set"}},
	{Parent: "kexec", Subcommands: []string{"debug"}},
}

func patchFishCompletionScript(script, appName string) string {
	// Fix urfave/cli's buggy root-level completion guard (see comment above).
	for _, pair := range [][2]string{
		{
			fmt.Sprintf("complete -c %s -n '__fish_%s_no_subcommand'", appName, appName),
			fmt.Sprintf("complete -c %s -n '__fish_use_subcommand'", appName),
		},
		{
			fmt.Sprintf("complete -r -c %s -n '__fish_%s_no_subcommand'", appName, appName),
			fmt.Sprintf("complete -r -c %s -n '__fish_use_subcommand'", appName),
		},
	} {
		script = strings.ReplaceAll(script, pair[0], pair[1])
	}

	// Scope each command's static completions so they stop firing once a deeper
	// subcommand token is already on the command line. Without this, urfave/cli's
	// generated entries bleed into argument-completion contexts and show subcommand
	// names as spurious candidates.
	for _, cmd := range fishScopedCmds {
		old := fmt.Sprintf("-n '__fish_seen_subcommand_from %s'", cmd.Parent)
		new := fmt.Sprintf("-n '__fish_seen_subcommand_from %s; and not __fish_seen_subcommand_from %s'",
			cmd.Parent, strings.Join(cmd.Subcommands, " "))
		script = strings.ReplaceAll(script, old, new)
	}

	script += buildDynamicFishCompletions(appName)
	return script
}

// dynamicFishCompletionsTmpl generates fish completion stanzas for argument-level
// completion. The helper function re-invokes the binary with the current token
// list plus --generate-bash-completion so that the Go BashComplete callbacks
// supply dynamic candidates (machine names, group names, secret keys).
// $t[1] re-uses the binary path as typed, so invocations via relative or
// absolute paths work without requiring the binary to be on PATH.
var dynamicFishCompletionsTmpl = template.Must(template.New("fish-dynamic").Parse(`
function __fish_{{.App}}_complete_dynamic
    set -l t (commandline -opc)
    $t[1] $t[2..] --generate-bash-completion 2>/dev/null
end
{{range .Commands}}{{$p := .Parent}}
complete -c {{$.App}} -f -n '__fish_seen_subcommand_from {{$p}}'
{{- range .Subcommands}}
complete -c {{$.App}} -f -n '__fish_seen_subcommand_from {{$p}}; and __fish_seen_subcommand_from {{.}}' -a "(__fish_{{$.App}}_complete_dynamic)"
{{- end}}
{{- end}}
`))

func buildDynamicFishCompletions(appName string) string {
	type entry struct {
		Parent      string
		Subcommands []string
	}
	data := struct {
		App      string
		Commands []entry
	}{App: appName}
	for _, cmd := range fishScopedCmds {
		data.Commands = append(data.Commands, entry{Parent: cmd.Parent, Subcommands: cmd.Subcommands})
	}
	var b bytes.Buffer
	if err := dynamicFishCompletionsTmpl.Execute(&b, data); err != nil {
		panic(err)
	}
	return b.String()
}

const configKey = "deploy.config"

func getConfig(ctx *cli.Context) *Config {
	return ctx.App.Metadata[configKey].(*Config)
}

// completionConfig builds a minimal Config from CLI flags without any validation.
// Used inside BashComplete functions because Before hooks are skipped during
// shell completion -- getConfig would panic since the metadata is never populated.
func completionConfig(ctx *cli.Context) *Config {
	flake := ctx.Path("flake")
	abs, _ := filepath.Abs(flake)
	resolve := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(abs, p)
	}
	return &Config{
		FlakeDir:  abs,
		SopsConf:  filepath.Join(abs, ".sops.yaml"),
		HostsFile: resolve(ctx.Path("hosts-file")),
	}
}

func requireSimpleName(kind, value string) (string, error) {
	if value == "" {
		return "", errors.Errorf("%s name is required", kind)
	}
	if !vars.ValidName(value) {
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

// requireMachineName validates a machine name, rejecting the directory name
// reserved for group secrets.
func requireMachineName(value string) (string, error) {
	machine, err := requireSimpleName("machine", value)
	if err != nil {
		return "", err
	}
	if machine == vars.SharedDirName {
		return "", errors.Errorf("machine name %q is reserved for group secrets", machine)
	}
	return machine, nil
}

func requireMachine(cfg *Config, value string) (string, error) {
	machine, err := requireMachineName(value)
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

// resolveTargetMachines expands each arg to a list of validated machine names.
// If an arg is a declared group it is replaced by its members; otherwise the
// arg is validated as a single machine name. Duplicates are dropped (first
// occurrence wins) so passing a group and one of its members is safe.
func resolveTargetMachines(cfg *Config, args []string) ([]string, error) {
	seen := make(map[string]struct{})
	var machines []string
	for _, arg := range args {
		isGroup, err := hosts.HasGroup(cfg.HostsFile, arg)
		if err != nil {
			return nil, err
		}
		if isGroup {
			members, err := hosts.GroupMembers(cfg.HostsFile, arg)
			if err != nil {
				return nil, errors.Wrapf(err, "expand group %q", arg)
			}
			for _, m := range members {
				if _, ok := seen[m]; ok {
					continue
				}
				if _, err := requireMachine(cfg, m); err != nil {
					return nil, errors.Wrapf(err, "group %q member %q", arg, m)
				}
				seen[m] = struct{}{}
				machines = append(machines, m)
			}
			continue
		}
		m, err := requireMachine(cfg, arg)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		machines = append(machines, m)
	}
	return machines, nil
}

// SSHOptions returns the common SSH option values derived from Config.
func (c *Config) SSHOptions() []string {
	return []string{
		"UserKnownHostsFile=" + c.KnownHosts,
		"GlobalKnownHostsFile=/dev/null",
		"StrictHostKeyChecking=accept-new",
		"UpdateHostKeys=no",
	}
}

// SSHArgs returns the common SSH option flags for the ssh executable.
func (c *Config) SSHArgs() []string {
	options := c.SSHOptions()
	args := make([]string, 0, len(options)*2)
	for _, option := range options {
		args = append(args, "-o", option)
	}
	return args
}

// NixOSAnywhereSSHArgs returns the common SSH options in nixos-anywhere syntax.
func (c *Config) NixOSAnywhereSSHArgs() []string {
	options := c.SSHOptions()
	args := make([]string, 0, len(options)*2)
	for _, option := range options {
		args = append(args, "--ssh-option", option)
	}
	return args
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
		Name:                 "deploy",
		Usage:                "NixOS machine management tool",
		EnableBashCompletion: true,
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
				FlakeDir:       abs,
				SopsConf:       filepath.Join(abs, ".sops.yaml"),
				HostsFile:      resolve(ctx.Path("hosts-file")),
				KnownHosts:     resolve(ctx.Path("known-hosts")),
				SSHUser:        ctx.String("ssh-user"),
				ImagesFlake:    ctx.String("images-flake"),
				System:         ctx.String("system"),
				SystemExplicit: ctx.IsSet("system"),
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
			groupCmd(),
			migrateCmd(),
			syncCmd(),
			machineCmd(),
			kexecCmd(),
			{
				Name:   "fish-completion",
				Usage:  "print fish shell completion script",
				Hidden: true,
				Action: func(ctx *cli.Context) error {
					ctx.App.Setup()
					s, err := ctx.App.ToFishCompletion()
					if err != nil {
						return err
					}
					s = patchFishCompletionScript(s, ctx.App.Name)
					_, err = fmt.Fprint(ctx.App.Writer, s)
					return err
				},
			},
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
	protectActions(app.Commands, "")
	return app
}
