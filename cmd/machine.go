package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/installer"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/nix"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

const (
	stdoutBarColor = "\x1b[1;37m"
	stderrBarColor = "\x1b[1;31m"

	sshControlMasterReadyTimeout = 30 * time.Second
	sshControlMasterStopTimeout  = 2 * time.Second
)

var labelColors = []string{
	"\x1b[32m",       // green
	"\x1b[33m",       // yellow
	"\x1b[34m",       // blue
	"\x1b[35m",       // magenta
	"\x1b[36m",       // cyan
	"\x1b[91m",       // bright red
	"\x1b[92m",       // bright green
	"\x1b[93m",       // bright yellow
	"\x1b[94m",       // bright blue
	"\x1b[95m",       // bright magenta
	"\x1b[96m",       // bright cyan
	"\x1b[38;5;208m", // orange
	"\x1b[38;5;172m", // dark orange
	"\x1b[38;5;141m", // light purple
	"\x1b[38;5;73m",  // steel blue
	"\x1b[38;5;156m", // light green
}

var errSSHControlMasterExitTimeout = errors.New("timed out waiting for ssh control master exit")

// writerConfig builds prefixed output writers for a single deploy.
// Label is empty for single-machine deploys (no prefix added).
type writerConfig struct {
	Label      string
	LabelColor string
}

func (c writerConfig) buildPrefix(barColor string) string {
	bar := barColor + "┃\x1b[0m "
	if c.Label == "" {
		return bar
	}
	return c.LabelColor + "[" + c.Label + "]\x1b[0m " + bar
}

func (c writerConfig) stdout() io.Writer {
	return newLinePrefixWriter(os.Stdout, c.buildPrefix(stdoutBarColor))
}

func (c writerConfig) stderr() io.Writer {
	return newLinePrefixWriter(os.Stderr, c.buildPrefix(stderrBarColor))
}

type linePrefixWriter struct {
	dst         io.Writer
	prefix      []byte
	atLineStart bool
}

func newLinePrefixWriter(dst io.Writer, prefix string) *linePrefixWriter {
	return &linePrefixWriter{
		dst:         dst,
		prefix:      []byte(prefix),
		atLineStart: true,
	}
}

func (w *linePrefixWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if w.atLineStart {
			if _, err := w.dst.Write(w.prefix); err != nil {
				return written, err
			}
			w.atLineStart = false
		}

		newline := bytes.IndexByte(p, '\n')
		chunkEnd := len(p)
		if newline >= 0 {
			chunkEnd = newline + 1
		}

		n, err := w.dst.Write(p[:chunkEnd])
		written += n
		if err != nil {
			return written, err
		}

		if newline >= 0 {
			w.atLineStart = true
		}
		p = p[chunkEnd:]
	}

	return written, nil
}

func machineCmd() *cli.Command {
	return &cli.Command{
		Name:  "machine",
		Usage: "NixOS machine lifecycle operations",
		Before: func(ctx *cli.Context) error {
			return requireFlake(getConfig(ctx))
		},
		Subcommands: []*cli.Command{
			machineInitCmd(),
			machineInspectCmd(),
			machineProvisionCmd(),
			machineBuildCmd(),
			machineEvalCmd(),
			machineAuditCmd(),
			machineDeployCmd(),
			machineSSHCmd(),
			machineUnlockZFSCmd(),
		},
	}
}

func machineInitCmd() *cli.Command {
	return &cli.Command{
		Name:      "init",
		Usage:     "bootstrap a machine via nixos-anywhere (kexec -> disko -> install -> reboot)",
		ArgsUsage: "<machine> <host>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "backend", Usage: "installation backend: nixos-anywhere or executable"},
			&cli.BoolFlag{Name: "build-only", Usage: "build declared installation artifacts without provisioning or running the installer"},
			&cli.IntFlag{
				Name:  "port",
				Usage: "SSH port on the target",
				Value: 22,
			},
			&cli.StringFlag{
				Name:  "phases",
				Usage: "nixos-anywhere phases to execute",
				Value: "kexec,disko,install,reboot",
			},
			&cli.StringFlag{
				Name:  "kexec-flavor",
				Usage: "kexec image flavor to auto-build: zfs or ext4",
				Value: "zfs",
			},
			&cli.PathFlag{
				Name:  "kexec",
				Usage: "path to kexec tarball; if empty, built from --images-flake",
			},
			&cli.StringSliceFlag{
				Name:  "ssh-option",
				Usage: "extra SSH option to prepend to nixos-anywhere SSH calls; can be repeated",
			},
		},
		Action: repositoryMutation(func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine init <machine> [host]")
			}
			cfg := getConfig(ctx)
			machine, err := requireMachine(cfg, ctx.Args().Get(0))
			if err != nil {
				return err
			}
			meta, err := machineMetadata(cfg, machine)
			if err != nil {
				return err
			}
			backend := ctx.String("backend")
			if backend == "" {
				backend = meta.Installer.Backend
			}
			meta.Installer.Backend = backend
			if err := validateInstaller(meta, backend); err != nil {
				return err
			}
			if ctx.Bool("build-only") {
				if err := requireMachinesProvisioned(cfg, machine); err != nil {
					return err
				}
				return buildInstallArtifacts(ctx, cfg, machine, meta)
			}
			handler, err := installationBackends.Resolve(backend)
			if err != nil {
				return err
			}
			if handler.SecretDelivery() == "out-of-band" {
				return executableInstall(ctx, cfg, machine, meta)
			}
			if ctx.NArg() != 2 {
				return errors.New("nixos-anywhere requires <machine> <host>")
			}
			if !cfg.SystemExplicit && meta.System == "" {
				return errors.New("cannot resolve target architecture; supply --system")
			}
			if !cfg.SystemExplicit && meta.System != "" {
				cfg.System = meta.System
			}
			host := ctx.Args().Get(1)
			port := ctx.Int("port")
			phases := ctx.String("phases")
			sshOptions := ctx.StringSlice("ssh-option")

			kexecTarball := ctx.Path("kexec")
			if kexecTarball == "" {
				flavor := ctx.String("kexec-flavor")
				if !ctx.IsSet("kexec-flavor") && meta.RootFS != "zfs" && len(meta.Pools) == 0 {
					flavor = "ext4"
				}
				log.Info().Str("flavor", flavor).Msg("no --kexec provided, building from images flake")
				kexecTarball, err = buildKexecTarball(cfg.ImagesFlake, cfg.System, flavor)
				if err != nil {
					return errors.Wrap(err, "auto-build kexec tarball")
				}
			}

			log.Info().Str("machine", machine).Str("host", host).Int("port", port).Msg("initialising machine")

			if err := provisionMachine(cfg, machine); err != nil {
				return err
			}

			extra, err := os.MkdirTemp("", "deploy-extra-*")
			if err != nil {
				return errors.Wrap(err, "create extra tmpdir")
			}
			defer func() { _ = os.RemoveAll(extra) }()

			// Decrypt openssh host key into extra files.
			if err := prepareExtraSSHKeys(cfg, machine, extra); err != nil {
				return err
			}

			// Decrypt ZFS root keys into temp files, one per encrypted pool.
			zfsKeyFiles, err := decryptZFSKeys(cfg, machine)
			if err != nil {
				return err
			}
			defer func() {
				for _, f := range zfsKeyFiles {
					_ = os.Remove(f)
				}
			}()

			// Decrypt initrd SSH keys into extra.
			if err := prepareInitrdKeys(cfg, machine, extra); err != nil {
				return err
			}

			// Build disko script and system toplevel.
			log.Info().Str("machine", machine).Msg("building disko script")
			diskoScript, err := nix.Build(cfg.FlakeDir, cfg.MachineAttr(machine, "config.system.build.diskoScript"))
			if err != nil {
				return errors.Wrapf(err, "build diskoScript for %s", machine)
			}

			log.Info().Str("machine", machine).Msg("building system toplevel")
			toplevel, err := nix.Build(cfg.FlakeDir, cfg.MachineAttr(machine, "config.system.build.toplevel"))
			if err != nil {
				return errors.Wrapf(err, "build toplevel for %s", machine)
			}

			args := []string{}
			for _, option := range sshOptions {
				args = append(args, "--ssh-option", option)
			}
			sshArgs := cfg.NixOSAnywhereSSHArgs()
			args = append(args, sshArgs...)
			args = append(args,
				"--phases", phases,
				"--post-kexec-ssh-port", "22",
				"--kexec", kexecTarball,
				"--no-substitute-on-destination",
				"--extra-files", extra,
			)
			for remotePath, localFile := range zfsKeyFiles {
				args = append(args, "--disk-encryption-keys", remotePath, localFile)
			}
			args = append(args,
				"--store-paths", diskoScript, toplevel,
				"-p", fmt.Sprintf("%d", port),
				cfg.SSHTarget(host),
			)

			wc := writerConfig{}
			log.Info().Str("machine", machine).Str("host", host).Int("port", port).Msg("running NixOS Anywhere")
			invocation, err := handler.Command(installer.Prepared{Arguments: args})
			if err != nil {
				return err
			}
			cmd := exec.CommandContext(ctx.Context, invocation.Program, invocation.Arguments...)
			cmd.Env = append(os.Environ(), "HOME="+cfg.FlakeDir)
			cmd.Stdin = os.Stdin
			cmd.Stdout = wc.stdout()
			cmd.Stderr = wc.stderr()
			if err := cmd.Run(); err != nil {
				return errors.Wrap(err, "nixos-anywhere")
			}

			if meta.YggdrasilAddressTag != "default" && meta.Addresses["default"] == "" {
				if err := hosts.SetAddress(cfg.HostsFile, machine, "", host); err != nil {
					return err
				}
			}
			if meta.Addresses["unlock"] == "" {
				if err := hosts.SetAddress(cfg.HostsFile, machine, "unlock", host); err != nil {
					return err
				}
			}
			log.Info().Str("machine", machine).Str("host", host).Msg("machine initialised")
			return nil
		}),
	}
}

func machineBuildCmd() *cli.Command {
	return &cli.Command{
		Name:      "build",
		Usage:     "build the NixOS system toplevel for one or more machines or groups",
		ArgsUsage: "<machine|group...>",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:  "parallel",
				Usage: "maximum number of concurrent builds",
				Value: 3,
			},
		},
		BashComplete: func(ctx *cli.Context) {
			cfg := completionConfig(ctx)
			for _, name := range completionMachineOrGroupNames(cfg) {
				fmt.Println(name)
			}
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine build <machine|group...>")
			}
			cfg := getConfig(ctx)
			parallelism := ctx.Int("parallel")

			machines, err := resolveTargetMachines(cfg, ctx.Args().Slice())
			if err != nil {
				return err
			}

			if err := requireMachinesProvisioned(cfg, machines...); err != nil {
				return err
			}

			usePrefix := len(machines) > 1

			type buildResult struct {
				machine string
				path    string
				err     error
			}

			sem := make(chan struct{}, parallelism)
			results := make(chan buildResult, len(machines))

			for i, machine := range machines {
				wc := writerConfig{}
				if usePrefix {
					wc = writerConfig{
						Label:      machine,
						LabelColor: labelColors[i%len(labelColors)],
					}
				}
				nixc := nix.NewClient(wc.stdout(), wc.stderr())

				sem <- struct{}{}
				go func(machine string, nixc *nix.Client) {
					defer func() { <-sem }()
					path, err := buildMachine(cfg, machine, nixc)
					results <- buildResult{machine: machine, path: path, err: err}
				}(machine, nixc)
			}

			var errs []error
			paths := make([]string, 0, len(machines))
			for range machines {
				result := <-results
				if result.err != nil {
					errs = append(errs, errors.Wrapf(result.err, "build %s", result.machine))
					continue
				}
				paths = append(paths, result.path)
			}
			if len(errs) > 0 {
				msgs := make([]string, len(errs))
				for i, err := range errs {
					msgs[i] = err.Error()
				}
				return errors.New(strings.Join(msgs, "\n"))
			}
			for _, path := range paths {
				fmt.Println(path)
			}
			return nil
		},
	}
}

func buildMachine(cfg *Config, machine string, nixc *nix.Client) (string, error) {
	log.Info().Str("machine", machine).Msg("building toplevel")
	path, err := nixc.Build(cfg.FlakeDir, cfg.MachineAttr(machine, "config.system.build.toplevel"))
	if err != nil {
		return "", err
	}
	return path, nil
}

func machineEvalCmd() *cli.Command {
	return &cli.Command{
		Name:      "eval",
		Usage:     "evaluate a NixOS config attribute and print as YAML",
		ArgsUsage: "<machine> <attr>",
		BashComplete: func(ctx *cli.Context) {
			cfg := completionConfig(ctx)
			if ctx.NArg() == 0 {
				for _, name := range completionMachineNames(cfg) {
					fmt.Println(name)
				}
			}
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 2 {
				return errors.New("usage: machine eval <machine> <attr>")
			}
			cfg := getConfig(ctx)
			machine, err := requireMachine(cfg, ctx.Args().Get(0))
			if err != nil {
				return err
			}
			if err := requireMachinesProvisioned(cfg, machine); err != nil {
				return err
			}

			attr := ctx.Args().Get(1)
			fullAttr := cfg.MachineAttr(machine, "config."+attr)
			log.Debug().Str("machine", machine).Str("attr", fullAttr).Msg("eval")
			raw, err := nix.Eval(cfg.FlakeDir, fullAttr)
			if err != nil {
				return errors.Wrapf(err, "eval %s.%s", machine, attr)
			}
			fmt.Println(string(raw))
			return nil
		},
	}
}

func machineAuditCmd() *cli.Command {
	return &cli.Command{
		Name:      "audit",
		Usage:     "check system closure for accidental source leaks",
		ArgsUsage: "<machine>",
		BashComplete: func(ctx *cli.Context) {
			cfg := completionConfig(ctx)
			if ctx.NArg() == 0 {
				for _, name := range completionMachineNames(cfg) {
					fmt.Println(name)
				}
			}
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine audit <machine>")
			}
			cfg := getConfig(ctx)
			machine, err := requireMachine(cfg, ctx.Args().Get(0))
			if err != nil {
				return err
			}

			if err := requireMachinesProvisioned(cfg, machine); err != nil {
				return err
			}

			meta, err := machineMetadata(cfg, machine)
			if err != nil {
				return err
			}
			attrs := map[string]string{"toplevel": cfg.MachineAttr(machine, "config.system.build.toplevel")}
			if meta.Disko {
				attrs["diskoScript"] = cfg.MachineAttr(machine, "config.system.build.diskoScript")
			}

			leakFound := false
			for label, attr := range attrs {
				log.Info().Str("machine", machine).Str("label", label).Msg("auditing closure")
				storePath, err := nix.Build(cfg.FlakeDir, attr)
				if err != nil {
					return errors.Wrapf(err, "build %s for audit", label)
				}
				deps, err := nix.PathInfo(storePath)
				if err != nil {
					return errors.Wrapf(err, "path-info for %s", label)
				}
				for _, dep := range deps {
					if !isSourcePath(dep) {
						continue
					}
					if !hasMachinesDir(dep) {
						continue
					}
					leakFound = true
					log.Warn().Str("label", label).Str("dep", dep).Msg("potential source leak")
					_ = nix.WhyDepends(storePath, dep)
				}
			}

			if leakFound {
				return errors.New("source leaks detected in closure")
			}
			log.Info().Str("machine", machine).Msg("audit passed — no leaks found")
			return nil
		},
	}
}

func machineDeployCmd() *cli.Command {
	return &cli.Command{
		Name:      "deploy",
		Usage:     "deploy the NixOS configuration to one or more machines or groups",
		ArgsUsage: "<machine|group...>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "host",
				Aliases: []string{"H"},
				Usage:   "override the target host address (single machine only)",
			},
			&cli.IntFlag{
				Name:  "parallel",
				Usage: "maximum number of concurrent deploys",
				Value: 3,
			},
		},
		BashComplete: func(ctx *cli.Context) {
			cfg := completionConfig(ctx)
			for _, name := range completionMachineOrGroupNames(cfg) {
				fmt.Println(name)
			}
		},
		Action: repositoryMutation(func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine deploy <machine|group...>")
			}
			cfg := getConfig(ctx)
			hostOverride := ctx.String("host")
			parallelism := ctx.Int("parallel")

			// Validate and expand all args (groups expand to their members) before
			// starting any deploy.
			machines, err := resolveTargetMachines(cfg, ctx.Args().Slice())
			if err != nil {
				return err
			}

			if hostOverride != "" && len(machines) > 1 {
				return errors.New("--host can only be used when deploying a single machine")
			}

			if err := requireMachinesProvisioned(cfg, machines...); err != nil {
				return err
			}

			// Resolve and register hosts up front.
			hostFor := make(map[string]string, len(machines))
			for _, machine := range machines {
				if hostOverride != "" {
					meta, err := machineMetadata(cfg, machine)
					if err != nil {
						return err
					}
					if meta.YggdrasilAddressTag != "default" && meta.Addresses["default"] == "" {
						if err := hosts.SetAddress(cfg.HostsFile, machine, "", hostOverride); err != nil {
							return errors.Wrapf(err, "register host for %s", machine)
						}
					}
					hostFor[machine] = hostOverride
				} else {
					h, err := hosts.GetAddress(cfg.HostsFile, machine, "ssh")
					if err != nil {
						return errors.Wrapf(err, "get host for %s", machine)
					}
					if h == "" {
						return errors.Errorf("no host registered for %s; pass --host or run machine init first", machine)
					}
					hostFor[machine] = h
				}
			}

			usePrefix := len(machines) > 1

			type deployResult struct {
				machine string
				err     error
			}

			sem := make(chan struct{}, parallelism)
			results := make(chan deployResult, len(machines))

			for i, machine := range machines {
				wc := writerConfig{}
				if usePrefix {
					wc = writerConfig{
						Label:      machine,
						LabelColor: labelColors[i%len(labelColors)],
					}
				}
				nixc := nix.NewClient(wc.stdout(), wc.stderr())

				sem <- struct{}{} // acquire slot; blocks when cap is reached
				go func(machine, targetHost string, wc writerConfig, nixc *nix.Client) {
					defer func() { <-sem }()
					results <- deployResult{machine, deployMachine(cfg, machine, targetHost, nixc, wc)}
				}(machine, hostFor[machine], wc, nixc)
			}

			var errs []error
			for range machines {
				r := <-results
				if r.err != nil {
					errs = append(errs, errors.Wrapf(r.err, "deploy %s", r.machine))
				}
			}
			if len(errs) == 0 {
				return nil
			}
			msgs := make([]string, len(errs))
			for i, e := range errs {
				msgs[i] = e.Error()
			}
			return errors.New(strings.Join(msgs, "\n"))
		}),
	}
}

func deployMachine(cfg *Config, machine, targetHost string, nixc *nix.Client, wc writerConfig) error {
	log.Info().Str("machine", machine).Str("host", targetHost).Msg("starting deployment")

	// Establish a per-deploy SSH config and ControlMaster so plain ssh
	// invocations and nix copy resolve the exact same target alias.
	controlDir, err := os.MkdirTemp("", "deploy-ctl-*")
	if err != nil {
		return errors.Wrap(err, "create control tmpdir")
	}
	defer func() { _ = os.RemoveAll(controlDir) }()
	controlPath := filepath.Join(controlDir, "ctl")
	sshConfigPath := filepath.Join(controlDir, "ssh_config")
	sshAlias := "deploy-target"

	sshConfig := strings.Join([]string{
		"Host " + sshAlias,
		"  HostName " + targetHost,
		"  User " + cfg.SSHUser,
		"  UserKnownHostsFile " + cfg.KnownHosts,
		"  GlobalKnownHostsFile /dev/null",
		"  StrictHostKeyChecking accept-new",
		"  UpdateHostKeys no",
		"  ControlMaster auto",
		"  ControlPath " + controlPath,
		"  ControlPersist 2h",
		"  ServerAliveInterval 60",
		"  ServerAliveCountMax 10",
		"",
	}, "\n")
	if err := os.WriteFile(sshConfigPath, []byte(sshConfig), 0o600); err != nil {
		return errors.Wrap(err, "write ssh config")
	}

	sshArgs := []string{"-F", sshConfigPath}
	log.Info().Str("machine", machine).Str("host", targetHost).Msg("opening ssh control connection")

	masterArgs := append(append([]string{}, sshArgs...),
		"-M",
		"-N", sshAlias,
	)
	master := exec.Command("ssh", masterArgs...)
	master.Stderr = wc.stderr()
	master.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	masterErrCh := make(chan error, 1)
	if err := master.Start(); err != nil {
		return errors.Wrap(err, "start ssh control master")
	}
	go func() {
		masterErrCh <- master.Wait()
	}()
	defer func() {
		if err := stopSSHControlMaster(master, masterErrCh, sshArgs, sshAlias); err != nil {
			log.Warn().Err(err).Str("host", targetHost).Msg("failed to stop ssh control master cleanly")
		}
	}()

	log.Debug().Str("host", targetHost).Msg("waiting for ssh control master")
	if err := waitForSSHControlMaster(masterErrCh, sshArgs, sshAlias, targetHost); err != nil {
		return err
	}
	log.Info().Str("machine", machine).Str("host", targetHost).Msg("ssh control connection ready")

	// Upload the managed ssh host key before activation so sops-nix
	// derives the expected age identity from /etc/ssh/ssh_host_ed25519_key.
	log.Info().Str("machine", machine).Msg("checking ssh host key")
	if err := uploadOpenSSHHostKey(cfg, machine, sshAlias, sshArgs, wc); err != nil {
		return err
	}

	// Upload initrd host keys.
	log.Info().Str("machine", machine).Msg("checking initrd ssh host keys")
	if err := uploadInitrdKeys(cfg, machine, sshAlias, sshArgs, nixc, wc); err != nil {
		return err
	}

	// Build and copy toplevel.
	log.Info().Str("machine", machine).Msg("building system toplevel")
	toplevel, err := nixc.Build(cfg.FlakeDir, cfg.MachineAttr(machine, "config.system.build.toplevel"))
	if err != nil {
		return errors.Wrapf(err, "build toplevel for %s", machine)
	}

	log.Info().Str("machine", machine).Str("host", targetHost).Msg("copying system closure")
	sshURL := "ssh://" + sshAlias
	if err := nixc.Copy(toplevel, sshURL, sshArgs); err != nil {
		return errors.Wrapf(err, "copy closure to %s", targetHost)
	}

	log.Info().Str("machine", machine).Msg("activating configuration")
	switchCmd := fmt.Sprintf(
		"nix-env --profile /nix/var/nix/profiles/system --set '%s' && "+
			"/nix/var/nix/profiles/system/bin/switch-to-configuration boot && "+
			"/nix/var/nix/profiles/system/bin/switch-to-configuration switch",
		toplevel,
	)
	runArgs := append(append([]string{}, sshArgs...), sshAlias, switchCmd)
	switchExec := exec.Command("ssh", runArgs...)
	switchExec.Stdout = wc.stdout()
	switchExec.Stderr = wc.stderr()
	if err := switchExec.Run(); err != nil {
		return errors.Wrap(err, "switch-to-configuration")
	}

	log.Info().Str("machine", machine).Msg("deployment complete")
	return nil
}

func machineSSHCmd() *cli.Command {
	return &cli.Command{
		Name:      "ssh",
		Usage:     "open an interactive SSH session to a machine",
		ArgsUsage: "<machine>",
		BashComplete: func(ctx *cli.Context) {
			cfg := completionConfig(ctx)
			if ctx.NArg() == 0 {
				for _, name := range completionMachineNames(cfg) {
					fmt.Println(name)
				}
			}
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine ssh <machine>")
			}
			cfg := getConfig(ctx)
			machine, err := requireMachine(cfg, ctx.Args().Get(0))
			if err != nil {
				return err
			}

			host, err := hosts.GetAddress(cfg.HostsFile, machine, "ssh")
			if err != nil {
				return errors.Wrapf(err, "get host for %s", machine)
			}
			if host == "" {
				return errors.Errorf("no host registered for %s; run machine init first", machine)
			}

			sshBin, err := exec.LookPath("ssh")
			if err != nil {
				return errors.Wrap(err, "find ssh binary")
			}

			args := append([]string{"ssh"}, cfg.SSHArgs()...)
			args = append(args, cfg.SSHTarget(host))

			log.Debug().Str("machine", machine).Str("host", host).Msg("exec ssh")
			return syscall.Exec(sshBin, args, os.Environ())
		},
	}
}

func machineUnlockZFSCmd() *cli.Command {
	return &cli.Command{
		Name:      "unlock",
		Usage:     "send the ZFS root key to the initrd SSH listener",
		ArgsUsage: "<machine>",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:  "initrd-port",
				Usage: "SSH port of the initrd listener",
				Value: 2222,
			},
		},
		BashComplete: func(ctx *cli.Context) {
			cfg := completionConfig(ctx)
			if ctx.NArg() == 0 {
				for _, name := range completionMachineNames(cfg) {
					fmt.Println(name)
				}
			}
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine unlock <machine>")
			}
			cfg := getConfig(ctx)
			machine, err := requireMachine(cfg, ctx.Args().Get(0))
			if err != nil {
				return err
			}
			if err := requireMachinesProvisioned(cfg, machine); err != nil {
				return err
			}

			meta, err := machineMetadata(cfg, machine)
			if err != nil {
				return err
			}
			initrdPort := meta.InitrdPort
			if ctx.IsSet("initrd-port") || initrdPort == 0 {
				initrdPort = ctx.Int("initrd-port")
			}
			if !meta.InitrdSSH {
				return errors.New("machine has no managed initrd SSH capability")
			}

			host, err := hosts.GetAddress(cfg.HostsFile, machine, "unlock")
			if err != nil {
				return errors.Wrapf(err, "get host for %s", machine)
			}
			if host == "" {
				return errors.Errorf("no host registered for %s; run machine init first", machine)
			}

			if meta.Unlock == "luks" {
				args := append(cfg.SSHArgs(), "-t", "-p", fmt.Sprint(initrdPort), cfg.SSHTarget(host), "unlock")
				command := exec.Command("ssh", args...)
				command.Stdin = os.Stdin
				command.Stdout = os.Stdout
				command.Stderr = os.Stderr
				return command.Run()
			}
			if meta.Unlock != "zfs" {
				return errors.New("no supported unlock capability declared")
			}
			log.Info().Str("machine", machine).Str("host", host).Int("port", initrdPort).Msg("unlocking ZFS")

			pools, err := encryptedZFSPools(cfg, machine)
			if err != nil {
				return err
			}
			if len(pools) == 0 {
				return errors.New("no encrypted ZFS pools declared")
			}

			secrets, err := sops.Open(vars.MachineSecretsPath(cfg.FlakeDir, machine))
			if err != nil {
				return errors.Wrapf(err, "open secrets for %s", machine)
			}
			wc := writerConfig{}
			for pool, remotePath := range pools {
				poolSpec := meta.Pools[pool]
				secretName := poolSpec.Secret
				if secretName == "" {
					secretName = zfsRootKeyName(pool)
				}
				key, err := secrets.Get(secretName)
				if err != nil {
					return errors.Wrapf(err, "read ZFS root key of pool %s for %s", pool, machine)
				}
				remoteCmd := fmt.Sprintf("mkdir -p -- %s && umask 077 && cat > %s && mv -- %s %s", shellArg(filepath.Dir(remotePath)), shellArg(remotePath+".tmp"), shellArg(remotePath+".tmp"), shellArg(remotePath))
				sshArgs := append(cfg.SSHArgs(), "-p", fmt.Sprintf("%d", initrdPort), cfg.SSHTarget(host), remoteCmd)
				cmd := exec.Command("ssh", sshArgs...)
				keyBytes, err := manifest.StorageKeyBytes(poolSpec, key)
				if err != nil {
					return err
				}
				cmd.Stdin = bytes.NewReader(keyBytes)
				cmd.Stdout = wc.stdout()
				cmd.Stderr = wc.stderr()
				if err := cmd.Run(); err != nil {
					return errors.Wrapf(err, "send %s key via ssh", pool)
				}
				log.Info().Str("machine", machine).Str("pool", pool).Msg("ZFS pool unlocked")
			}

			log.Info().Str("machine", machine).Msg("ZFS unlocked")
			return nil
		},
	}
}

// --- helpers ---

func prepareExtraSSHKeys(cfg *Config, machine, extraDir string) error {
	srcPriv := vars.MachineHostKeyPath(cfg.FlakeDir, machine)
	srcPub := vars.MachineHostKeyPubPath(cfg.FlakeDir, machine)

	dstDir := filepath.Join(extraDir, "etc", "ssh")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return errors.Wrap(err, "create extra etc/ssh")
	}

	log.Debug().Str("machine", machine).Msg("decrypting host ssh key for extra files")
	privPEM, err := sops.ReadFile(srcPriv)
	if err != nil {
		return errors.Wrapf(err, "decrypt host private key for %s", machine)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "ssh_host_ed25519_key"), privPEM, 0o600); err != nil {
		return errors.Wrap(err, "write host private key to extra")
	}

	pubBytes, err := os.ReadFile(srcPub)
	if err != nil {
		return errors.Wrapf(err, "read host public key for %s", machine)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "ssh_host_ed25519_key.pub"), pubBytes, 0o644); err != nil {
		return errors.Wrap(err, "write host public key to extra")
	}
	return nil
}

func waitForSSHControlMaster(masterErrCh <-chan error, sshArgs []string, sshAlias, targetHost string) error {
	checkArgs := append(append([]string{}, sshArgs...),
		"-O", "check", sshAlias,
	)
	deadline := time.Now().Add(sshControlMasterReadyTimeout)

	for time.Now().Before(deadline) {
		if exec.Command("ssh", checkArgs...).Run() == nil {
			return nil
		}

		select {
		case err := <-masterErrCh:
			if err != nil {
				return errors.Wrap(err, "ssh control master exited")
			}
			return errors.New("ssh control master exited unexpectedly")
		default:
		}

		time.Sleep(100 * time.Millisecond)
	}

	return errors.Errorf("timed out waiting for ssh control master to %s after %s", targetHost, sshControlMasterReadyTimeout)
}

func stopSSHControlMaster(master *exec.Cmd, masterErrCh <-chan error, sshArgs []string, sshAlias string) error {
	if master == nil || master.Process == nil {
		return nil
	}

	exitArgs := append(append([]string{}, sshArgs...),
		"-O", "exit", sshAlias,
	)
	if err := exec.Command("ssh", exitArgs...).Run(); err == nil {
		return waitForSSHControlMasterExit(masterErrCh, sshControlMasterStopTimeout)
	}

	if err := terminateSSHControlMaster(master.Process.Pid, masterErrCh, syscall.SIGTERM); err != nil {
		return err
	}

	if err := waitForSSHControlMasterExit(masterErrCh, sshControlMasterStopTimeout); err == nil {
		return nil
	} else if !errors.Is(err, errSSHControlMasterExitTimeout) {
		return err
	}

	if err := terminateSSHControlMaster(master.Process.Pid, masterErrCh, syscall.SIGKILL); err != nil {
		return err
	}

	return waitForSSHControlMasterExit(masterErrCh, sshControlMasterStopTimeout)
}

func waitForSSHControlMasterExit(masterErrCh <-chan error, timeout time.Duration) error {
	select {
	case err := <-masterErrCh:
		if err == nil {
			return nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil
		}
		return errors.Wrap(err, "wait for ssh control master exit")
	case <-time.After(timeout):
		return errSSHControlMasterExitTimeout
	}
}

func terminateSSHControlMaster(pid int, masterErrCh <-chan error, signal syscall.Signal) error {
	select {
	case err := <-masterErrCh:
		if err == nil {
			return nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil
		}
		return errors.Wrap(err, "ssh control master exited before signal")
	default:
	}

	if err := syscall.Kill(-pid, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
		return errors.Wrapf(err, "signal ssh control master with %s", signal)
	}

	return nil
}

// encryptedZFSPools returns a map of pool name → remote key path for every
// ZFS pool that uses file-based encryption.
//
// The preferred source is explicit initrd unlock metadata from
// config.modules.zfs-crypt.pools. Disko rootFsOptions are used as a fallback for
// machines that declare their encrypted pools through config.disko.devices.zpool.
func encryptedZFSPools(cfg *Config, machine string) (map[string]string, error) {
	meta, err := machineMetadata(cfg, machine)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for name, pool := range meta.Pools {
		result[name] = pool.KeyPath
	}
	return result, nil
}

// decryptZFSKeys decrypts the ZFS root key for every encrypted pool and writes
// each into a temp file. Returns a map of remote path → local tmpfile path.
func decryptZFSKeys(cfg *Config, machine string) (map[string]string, error) {
	meta, err := machineMetadata(cfg, machine)
	if err != nil {
		return nil, err
	}
	pools, err := encryptedZFSPools(cfg, machine)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(pools))
	complete := false
	defer func() {
		if !complete {
			for _, path := range result {
				_ = os.Remove(path)
			}
		}
	}()
	if len(pools) == 0 {
		return result, nil
	}
	secrets, err := sops.Open(vars.MachineSecretsPath(cfg.FlakeDir, machine))
	if err != nil {
		return nil, errors.Wrapf(err, "open secrets for %s", machine)
	}
	for pool, remotePath := range pools {
		log.Debug().Str("machine", machine).Str("pool", pool).Msg("decrypting ZFS root key")
		poolSpec := meta.Pools[pool]
		secretName := poolSpec.Secret
		if secretName == "" {
			secretName = zfsRootKeyName(pool)
		}
		key, err := secrets.Get(secretName)
		if err != nil {
			return nil, errors.Wrapf(err, "read ZFS root key of pool %s for %s", pool, machine)
		}
		f, err := os.CreateTemp("", "deploy-zfskey-*")
		if err != nil {
			return nil, errors.Wrap(err, "create zfs key tmpfile")
		}
		keyBytes, err := manifest.StorageKeyBytes(poolSpec, key)
		if err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return nil, err
		}
		result[remotePath] = f.Name()
		if _, err := f.Write(keyBytes); err != nil {
			_ = f.Close()
			return nil, errors.Wrap(err, "write zfs key")
		}
		if err := f.Close(); err != nil {
			return nil, errors.Wrap(err, "close zfs key tmpfile")
		}
		if err := os.Chmod(f.Name(), 0o400); err != nil {
			return nil, errors.Wrap(err, "chmod zfs key file")
		}
		result[remotePath] = f.Name()
	}
	complete = true
	return result, nil
}

// provisionMachine idempotently creates every key and secrets file a machine
// needs and syncs recipients. It never replaces existing keys.
func provisionMachine(cfg *Config, machine string) error {
	meta, err := machineMetadata(cfg, machine)
	if err != nil {
		return err
	}
	if err := ensureSopsConf(cfg); err != nil {
		return err
	}
	if meta.HostKey {
		if err := ensureHostKey(cfg, machine); err != nil {
			return err
		}
	}
	if meta.InitrdSSH {
		if err := ensureInitrdKey(cfg, machine); err != nil {
			return err
		}
	}
	if err := createEncryptedYAMLIfMissing(cfg, vars.MachineSecretsPath(cfg.FlakeDir, machine), "machine", machine); err != nil {
		return err
	}
	if err := syncAllRecipients(cfg); err != nil {
		return err
	}
	if err := ensureZFSKey(cfg, machine); err != nil {
		return err
	}
	return provisionApplicationResources(cfg, machine, meta)
}

// requireMachinesProvisioned checks, without decrypting or writing anything,
// that each machine has its keys and secrets file and that recipients are in
// sync.
func requireMachinesProvisioned(cfg *Config, machines ...string) error {
	if err := ensureSopsConf(cfg); err != nil {
		return err
	}
	for _, machine := range machines {
		var missing []string
		meta, err := machineMetadata(cfg, machine)
		if err != nil {
			return err
		}
		paths := []string{vars.MachineSecretsPath(cfg.FlakeDir, machine)}
		if meta.HostKey {
			paths = append(paths, vars.MachineHostKeyPath(cfg.FlakeDir, machine), vars.MachineHostKeyPubPath(cfg.FlakeDir, machine))
		}
		if meta.InitrdSSH {
			paths = append(paths, vars.MachineInitrdKeyPath(cfg.FlakeDir, machine), vars.MachineInitrdKeyPubPath(cfg.FlakeDir, machine))
		}
		for _, path := range paths {
			if !fileExists(path) {
				missing = append(missing, relToFlake(cfg, path))
			}
		}
		if err := requireApplicationResources(cfg, machine, meta); err != nil {
			return err
		}
		if len(missing) > 0 {
			return errors.Errorf("machine %s is not provisioned (missing %s); run 'deploy machine provision %s'",
				machine, strings.Join(missing, ", "), machine)
		}
	}
	return requireRecipientsInSync(cfg)
}

func machineProvisionCmd() *cli.Command {
	return &cli.Command{
		Name:      "provision",
		Usage:     "create missing host/initrd keys, secrets file and ZFS root keys, then sync recipients",
		ArgsUsage: "<machine|group...>",
		BashComplete: func(ctx *cli.Context) {
			cfg := completionConfig(ctx)
			for _, name := range completionMachineOrGroupNames(cfg) {
				fmt.Fprintln(ctx.App.Writer, name)
			}
		},
		Action: repositoryMutation(func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine provision <machine|group...>")
			}
			cfg := getConfig(ctx)
			machines, err := resolveTargetMachines(cfg, ctx.Args().Slice())
			if err != nil {
				return err
			}
			for _, machine := range machines {
				if err := provisionMachine(cfg, machine); err != nil {
					return errors.Wrapf(err, "provision %s", machine)
				}
			}
			return nil
		}),
	}
}

// ensureZFSKey generates and stores a ZFS root key for every encrypted pool
// that doesn't already have one in secrets.yaml.
func ensureZFSKey(cfg *Config, machine string) error {
	meta, err := machineMetadata(cfg, machine)
	if err != nil {
		return err
	}
	if len(meta.Pools) == 0 {
		return nil
	}
	names := make([]string, 0, len(meta.Pools))
	for name := range meta.Pools {
		names = append(names, name)
	}
	sort.Strings(names)
	return sops.Edit(vars.MachineSecretsPath(cfg.FlakeDir, machine), func(file *sops.File) error {
		for _, name := range names {
			pool := meta.Pools[name]
			if pool.Secret == "" {
				pool.Secret = zfsRootKeyName(name)
			}
			if _, err := file.SetIfAbsent(pool.Secret, func() (string, error) { return manifest.GenerateStorageKey(pool.Format) }); err != nil {
				return err
			}
			value, err := file.Get(pool.Secret)
			if err != nil {
				return err
			}
			if _, err := manifest.StorageKeyBytes(pool, value); err != nil {
				return err
			}
		}
		return nil
	})
}

// ensureZFSPoolKeys creates missing root keys for pools in a single
// decrypt/encrypt cycle. Existing keys are never replaced, and a decryption
// failure aborts without writing.
func ensureZFSPoolKeys(path, machine string, pools []string) error {
	if len(pools) == 0 {
		return nil
	}
	return sops.Edit(path, func(f *sops.File) error {
		for _, pool := range pools {
			created, err := f.SetIfAbsent(zfsRootKeyName(pool), generateZFSKey)
			if err != nil {
				return errors.Wrapf(err, "ensure ZFS root key of pool %s for %s", pool, machine)
			}
			if created {
				log.Info().Str("machine", machine).Str("pool", pool).Msg("wrote new ZFS root key")
			} else {
				log.Debug().Str("machine", machine).Str("pool", pool).Msg("ZFS key already present")
			}
		}
		return nil
	})
}

func zfsRootKeyName(pool string) string {
	return pool + "-root-key"
}

func generateZFSKey() (string, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", errors.Wrap(err, "generate ZFS key")
	}
	return hex.EncodeToString(keyBytes), nil
}

func prepareInitrdKeys(cfg *Config, machine, extraDir string) error {
	meta, err := machineMetadata(cfg, machine)
	if err != nil {
		return err
	}
	if !meta.InitrdSSH {
		return nil
	}
	raw, err := nix.Eval(cfg.FlakeDir, cfg.MachineAttr(machine, "config.boot.initrd.network.ssh.hostKeys"))
	if err != nil {
		return errors.Wrapf(err, "eval initrd host keys for %s", machine)
	}
	var hostKeys []string
	if err := json.Unmarshal(raw, &hostKeys); err != nil {
		return errors.Wrap(err, "parse initrd host keys")
	}

	for _, hostKeyPath := range hostKeys {
		localKey, err := initrdLocalKey(filepath.Base(hostKeyPath))
		if err != nil {
			return err
		}
		localSecret := filepath.Join(vars.MachineInitrdKeyDir(cfg.FlakeDir, machine), localKey)
		if !fileExists(localSecret) {
			return errors.Errorf("missing initrd SSH key for %s: %s", hostKeyPath, localSecret)
		}
		log.Debug().Str("key", hostKeyPath).Msg("decrypting initrd host key")
		privPEM, err := sops.ReadFile(localSecret)
		if err != nil {
			return errors.Wrapf(err, "decrypt initrd key %s", localSecret)
		}
		dst := filepath.Join(extraDir, hostKeyPath)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return errors.Wrapf(err, "create dir for initrd key %s", dst)
		}
		if err := os.WriteFile(dst, privPEM, 0o600); err != nil {
			return errors.Wrapf(err, "write initrd key %s", dst)
		}
	}
	return nil
}

func uploadOpenSSHHostKey(cfg *Config, machine, targetHost string, sshArgs []string, wc writerConfig) error {
	const hostKeyPath = "/etc/ssh/ssh_host_ed25519_key"

	localPublic := vars.MachineHostKeyPubPath(cfg.FlakeDir, machine)
	localSecret := vars.MachineHostKeyPath(cfg.FlakeDir, machine)
	if !fileExists(localSecret) {
		return errors.Errorf("missing ssh host key %s", localSecret)
	}
	if !fileExists(localPublic) {
		return errors.Errorf("missing ssh host public key %s", localPublic)
	}

	pubLine, err := os.ReadFile(localPublic)
	if err != nil {
		return errors.Wrapf(err, "read ssh host public key %s", localPublic)
	}

	log.Info().Str("path", hostKeyPath).Msg("checking remote ssh host key")
	matches, err := remoteKeyMatches(targetHost, sshArgs, hostKeyPath, pubLine, "ssh host key")
	if err != nil {
		return err
	}
	if matches {
		log.Info().Str("path", hostKeyPath).Msg("remote ssh host key already matches, skipping decrypt/upload")
		return nil
	}

	log.Info().Str("path", hostKeyPath).Msg("remote ssh host key differs or is missing, decrypting local key")
	privPEM, err := sops.ReadFile(localSecret)
	if err != nil {
		return errors.Wrapf(err, "decrypt ssh host key %s", localSecret)
	}

	log.Info().Str("path", hostKeyPath).Msg("uploading ssh host key")
	return uploadPrivateKey(targetHost, sshArgs, hostKeyPath, privPEM, wc)
}

func uploadInitrdKeys(cfg *Config, machine, targetHost string, sshArgs []string, nixc *nix.Client, wc writerConfig) error {
	meta, err := machineMetadata(cfg, machine)
	if err != nil {
		return err
	}
	if !meta.InitrdSSH {
		return nil
	}
	raw, err := nixc.Eval(cfg.FlakeDir, cfg.MachineAttr(machine, "config.boot.initrd.network.ssh.hostKeys"))
	if err != nil {
		return errors.Wrapf(err, "eval initrd host keys for %s", machine)
	}
	var hostKeys []string
	if err := json.Unmarshal(raw, &hostKeys); err != nil {
		return errors.Wrap(err, "parse initrd host keys")
	}

	sshTarget := cfg.SSHTarget(targetHost)
	for _, hostKeyPath := range hostKeys {
		localKey, err := initrdLocalKey(filepath.Base(hostKeyPath))
		if err != nil {
			return err
		}
		localPublic := filepath.Join(vars.MachineInitrdKeyDir(cfg.FlakeDir, machine), localKey+".pub")
		localSecret := filepath.Join(vars.MachineInitrdKeyDir(cfg.FlakeDir, machine), localKey)
		if !fileExists(localSecret) {
			return errors.Errorf("missing initrd SSH key %s", localSecret)
		}
		if !fileExists(localPublic) {
			return errors.Errorf("missing initrd SSH public key %s", localPublic)
		}

		pubLine, err := os.ReadFile(localPublic)
		if err != nil {
			return errors.Wrapf(err, "read initrd public key %s", localPublic)
		}

		log.Info().Str("path", hostKeyPath).Msg("checking remote initrd host key")
		matches, err := remoteKeyMatches(targetHost, sshArgs, hostKeyPath, pubLine, "initrd host key")
		if err != nil {
			return err
		}
		if matches {
			log.Info().Str("path", hostKeyPath).Msg("remote initrd host key already matches, skipping decrypt/upload")
			continue
		}

		log.Info().Str("path", hostKeyPath).Msg("remote initrd host key differs or is missing, decrypting local key")
		privPEM, err := sops.ReadFile(localSecret)
		if err != nil {
			return errors.Wrapf(err, "decrypt initrd key %s", localSecret)
		}

		log.Info().Str("path", hostKeyPath).Msg("uploading initrd host key")
		if err := uploadPrivateKey(sshTarget, sshArgs, hostKeyPath, privPEM, wc); err != nil {
			return errors.Wrapf(err, "upload initrd key %s", hostKeyPath)
		}
	}
	return nil
}

func remoteKeyMatches(targetHost string, sshArgs []string, hostKeyPath string, localPublic []byte, keyLabel string) (bool, error) {
	remoteCmd := fmt.Sprintf("test -r '%s' && ssh-keygen -y -f '%s' 2>/dev/null", hostKeyPath, hostKeyPath)
	runArgs := append(append([]string{}, sshArgs...), targetHost, remoteCmd)
	cmd := exec.Command("ssh", runArgs...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				log.Info().Str("path", hostKeyPath).Str("kind", keyLabel).Msg("remote key not present yet")
				return false, nil
			}
			return false, errors.Wrapf(err, "inspect remote %s %s", keyLabel, hostKeyPath)
		}
		return false, errors.Wrapf(err, "inspect remote %s %s", keyLabel, hostKeyPath)
	}

	remoteNormalized := normalizeAuthorizedKey(out)
	localNormalized := normalizeAuthorizedKey(localPublic)
	if remoteNormalized == localNormalized {
		return true, nil
	}

	log.Info().
		Str("path", hostKeyPath).
		Str("kind", keyLabel).
		Str("remote", remoteNormalized).
		Str("local", localNormalized).
		Msg("remote key does not match local public key")
	return false, nil
}

func uploadPrivateKey(targetHost string, sshArgs []string, hostKeyPath string, privPEM []byte, wc writerConfig) error {
	remoteCmd := fmt.Sprintf(
		"mkdir -p '%s' && umask 077 && cat > '%s.tmp' && mv '%s.tmp' '%s'",
		filepath.Dir(hostKeyPath), hostKeyPath, hostKeyPath, hostKeyPath,
	)
	runArgs := append(append([]string{}, sshArgs...), targetHost, remoteCmd)
	cmd := exec.Command("ssh", runArgs...)
	cmd.Stdin = bytes.NewReader(privPEM)
	cmd.Stderr = wc.stderr()
	return cmd.Run()
}

func normalizeAuthorizedKey(line []byte) string {
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return strings.TrimSpace(string(line))
	}
	return fields[0] + " " + fields[1]
}

func initrdLocalKey(base string) (string, error) {
	switch {
	case strings.HasSuffix(base, "_ed25519_key"):
		return "id_ed25519", nil
	case strings.HasSuffix(base, "_rsa_key"):
		return "id_rsa", nil
	case strings.HasSuffix(base, "_ecdsa_key"):
		return "id_ecdsa", nil
	}
	return "", errors.Errorf("unsupported initrd SSH host key path: %s", base)
}

func isSourcePath(path string) bool {
	// Nix source paths contain "-source" suffix.
	return len(path) > 7 && path[len(path)-7:] == "-source"
}

func hasMachinesDir(nixStorePath string) bool {
	fi, err := os.Stat(filepath.Join(nixStorePath, "machines"))
	return err == nil && fi.IsDir()
}
