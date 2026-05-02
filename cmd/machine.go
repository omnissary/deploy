package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/nix"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
)

func machineCmd() *cli.Command {
	return &cli.Command{
		Name:  "machine",
		Usage: "NixOS machine lifecycle operations",
		Before: func(ctx *cli.Context) error {
			return requireFlake(getConfig(ctx))
		},
		Subcommands: []*cli.Command{
			machineInitCmd(),
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
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 2 {
				return errors.New("usage: machine init <machine> <host>")
			}
			cfg := getConfig(ctx)
			machine := ctx.Args().Get(0)
			host := ctx.Args().Get(1)
			port := ctx.Int("port")
			phases := ctx.String("phases")

			kexecTarball := ctx.Path("kexec")
			if kexecTarball == "" {
				flavor := ctx.String("kexec-flavor")
				log.Info().Str("flavor", flavor).Msg("no --kexec provided, building from images flake")
				var err error
				kexecTarball, err = buildKexecTarball(cfg.ImagesFlake, cfg.System, flavor)
				if err != nil {
					return errors.Wrap(err, "auto-build kexec tarball")
				}
			}

			log.Info().Str("machine", machine).Str("host", host).Int("port", port).Msg("initialising machine")

			if err := ensureHostKey(cfg, machine); err != nil {
				return err
			}
			if err := ensureInitrdKey(cfg, machine); err != nil {
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

			// Decrypt ZFS root key into a temp file.
			zfsKeyFile, err := decryptZFSKey(cfg, machine)
			if err != nil {
				return err
			}
			defer func() { _ = os.Remove(zfsKeyFile) }()

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

			sshArgs := cfg.SSHArgs()
			args := []string{"--"}
			args = append(args, sshArgs...)
			args = append(args,
				"--phases", phases,
				"--post-kexec-ssh-port", "22",
				"--kexec", kexecTarball,
				"--no-substitute-on-destination",
				"--extra-files", extra,
				"--disk-encryption-keys", "/run/zfs-keys/rpool.key", zfsKeyFile,
				"--store-paths", diskoScript, toplevel,
				"-p", fmt.Sprintf("%d", port),
				cfg.SSHTarget(host),
			)

			log.Info().Str("machine", machine).Str("host", host).Int("port", port).Msg("running nixos-anywhere")
			cmd := exec.Command("nixos-anywhere", args...)
			cmd.Env = append(os.Environ(), "HOME="+cfg.FlakeDir)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return errors.Wrap(err, "nixos-anywhere")
			}

			if err := hosts.Set(cfg.HostsFile, machine, host); err != nil {
				return errors.Wrapf(err, "register host for %s", machine)
			}
			log.Info().Str("machine", machine).Str("host", host).Msg("machine initialised")
			return nil
		},
	}
}

func machineBuildCmd() *cli.Command {
	return &cli.Command{
		Name:      "build",
		Usage:     "build the NixOS system toplevel",
		ArgsUsage: "<machine>",
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine build <machine>")
			}
			cfg := getConfig(ctx)
			machine := ctx.Args().Get(0)

			if err := ensureHostKey(cfg, machine); err != nil {
				return err
			}
			if err := ensureInitrdKey(cfg, machine); err != nil {
				return err
			}

			log.Info().Str("machine", machine).Msg("building toplevel")
			path, err := nix.Build(cfg.FlakeDir, cfg.MachineAttr(machine, "config.system.build.toplevel"))
			if err != nil {
				return errors.Wrapf(err, "build %s", machine)
			}
			fmt.Println(path)
			return nil
		},
	}
}

func machineEvalCmd() *cli.Command {
	return &cli.Command{
		Name:      "eval",
		Usage:     "evaluate a NixOS config attribute and print as YAML",
		ArgsUsage: "<machine> <attr>",
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 2 {
				return errors.New("usage: machine eval <machine> <attr>")
			}
			cfg := getConfig(ctx)
			machine := ctx.Args().Get(0)
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
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine audit <machine>")
			}
			cfg := getConfig(ctx)
			machine := ctx.Args().Get(0)

			if err := ensureHostKey(cfg, machine); err != nil {
				return err
			}
			if err := ensureInitrdKey(cfg, machine); err != nil {
				return err
			}

			attrs := map[string]string{
				"diskoScript": cfg.MachineAttr(machine, "config.system.build.diskoScript"),
				"toplevel":    cfg.MachineAttr(machine, "config.system.build.toplevel"),
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
		Usage:     "deploy the NixOS configuration to a running machine",
		ArgsUsage: "<machine>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "host",
				Aliases: []string{"H"},
				Usage:   "override the target host address",
			},
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine deploy <machine>")
			}
			cfg := getConfig(ctx)
			machine := ctx.Args().Get(0)
			hostOverride := ctx.String("host")

			if err := ensureHostKey(cfg, machine); err != nil {
				return err
			}
			if err := ensureInitrdKey(cfg, machine); err != nil {
				return err
			}

			// Resolve host.
			var targetHost string
			if hostOverride != "" {
				targetHost = hostOverride
				if err := hosts.Set(cfg.HostsFile, machine, targetHost); err != nil {
					return errors.Wrapf(err, "register host for %s", machine)
				}
			} else {
				h, err := hosts.Get(cfg.HostsFile, machine)
				if err != nil {
					return errors.Wrapf(err, "get host for %s", machine)
				}
				if h == "" {
					return errors.Errorf("no host registered for %s; pass --host or run machine init first", machine)
				}
				targetHost = h
			}

			log.Info().Str("machine", machine).Str("host", targetHost).Msg("deploying")

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
				"  ControlPersist 10m",
				"",
			}, "\n")
			if err := os.WriteFile(sshConfigPath, []byte(sshConfig), 0o600); err != nil {
				return errors.Wrap(err, "write ssh config")
			}

			sshArgs := []string{"-F", sshConfigPath}
			log.Info().Str("machine", machine).Str("host", targetHost).Msg("opening SSH control connection")

			masterArgs := append(append([]string{}, sshArgs...),
				"-M",
				"-N", sshAlias,
			)
			master := exec.Command("ssh", masterArgs...)
			master.Stderr = os.Stderr
			if err := master.Start(); err != nil {
				return errors.Wrap(err, "start ssh control master")
			}
			defer func() {
				checkArgs := append(append([]string{}, sshArgs...),
					"-O", "exit", sshAlias,
				)
				_ = exec.Command("ssh", checkArgs...).Run()
				_ = master.Wait()
			}()

			// Wait until ControlMaster is ready.
			checkArgs := append(append([]string{}, sshArgs...),
				"-O", "check", sshAlias,
			)
			log.Debug().Str("host", targetHost).Msg("waiting for ssh control master")
			ready := false
			for i := 0; i < 100; i++ {
				if exec.Command("ssh", checkArgs...).Run() == nil {
					ready = true
					break
				}
				if master.ProcessState != nil {
					return errors.New("ssh control master exited unexpectedly")
				}
				time.Sleep(100 * time.Millisecond)
			}
			if !ready {
				return errors.Errorf("timed out waiting for ssh control master to %s", targetHost)
			}
			log.Info().Str("machine", machine).Str("host", targetHost).Msg("SSH control connection ready")

			// Upload the managed OpenSSH host key before activation so sops-nix
			// derives the expected age identity from /etc/ssh/ssh_host_ed25519_key.
			log.Info().Str("machine", machine).Msg("checking OpenSSH host key")
			if err := uploadOpenSSHHostKey(cfg, machine, sshAlias, sshArgs); err != nil {
				return err
			}

			// Upload initrd host keys.
			log.Info().Str("machine", machine).Msg("checking initrd SSH host keys")
			if err := uploadInitrdKeys(cfg, machine, sshAlias, sshArgs); err != nil {
				return err
			}

			// Build and copy toplevel.
			log.Info().Str("machine", machine).Msg("building toplevel")
			toplevel, err := nix.Build(cfg.FlakeDir, cfg.MachineAttr(machine, "config.system.build.toplevel"))
			if err != nil {
				return errors.Wrapf(err, "build toplevel for %s", machine)
			}

			log.Info().Str("machine", machine).Str("host", targetHost).Msg("copying closure")
			sshURL := "ssh://" + sshAlias
			if err := nix.Copy(toplevel, sshURL, sshArgs); err != nil {
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
			switchExec.Stdout = os.Stdout
			switchExec.Stderr = os.Stderr
			if err := switchExec.Run(); err != nil {
				return errors.Wrap(err, "switch-to-configuration")
			}

			log.Info().Str("machine", machine).Msg("deploy complete")
			return nil
		},
	}
}

func machineSSHCmd() *cli.Command {
	return &cli.Command{
		Name:      "ssh",
		Usage:     "open an interactive SSH session to a machine",
		ArgsUsage: "<machine>",
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine ssh <machine>")
			}
			cfg := getConfig(ctx)
			machine := ctx.Args().Get(0)

			host, err := hosts.Get(cfg.HostsFile, machine)
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
		Name:      "unlock-zfs",
		Usage:     "send the ZFS root key to the initrd SSH listener",
		ArgsUsage: "<machine>",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:  "initrd-port",
				Usage: "SSH port of the initrd listener",
				Value: 2222,
			},
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() < 1 {
				return errors.New("usage: machine unlock-zfs <machine>")
			}
			cfg := getConfig(ctx)
			machine := ctx.Args().Get(0)
			initrdPort := ctx.Int("initrd-port")

			host, err := hosts.Get(cfg.HostsFile, machine)
			if err != nil {
				return errors.Wrapf(err, "get host for %s", machine)
			}
			if host == "" {
				return errors.Errorf("no host registered for %s; run machine init first", machine)
			}

			log.Info().Str("machine", machine).Str("host", host).Int("port", initrdPort).Msg("unlocking ZFS")

			key, err := sops.DecryptYAMLExtract(
				filepath.Join(cfg.FlakeDir, "machines", machine, "secrets.yaml"),
				"zfs-root-key",
			)
			if err != nil {
				return errors.Wrapf(err, "decrypt zfs-root-key for %s", machine)
			}

			remoteCmd := "mkdir -p /run/zfs-keys && cat > /run/zfs-keys/rpool.key.tmp && mv /run/zfs-keys/rpool.key.tmp /run/zfs-keys/rpool.key"
			sshArgs := append(cfg.SSHArgs(), "-p", fmt.Sprintf("%d", initrdPort), cfg.SSHTarget(host), remoteCmd)
			cmd := exec.Command("ssh", sshArgs...)
			cmd.Stdin = strings.NewReader(key)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return errors.Wrap(err, "send zfs key via ssh")
			}

			log.Info().Str("machine", machine).Msg("ZFS unlocked")
			return nil
		},
	}
}

// --- helpers ---

func prepareExtraSSHKeys(cfg *Config, machine, extraDir string) error {
	srcPriv := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "openssh", "ssh_host_ed25519_key")
	srcPub := srcPriv + ".pub"

	dstDir := filepath.Join(extraDir, "etc", "ssh")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return errors.Wrap(err, "create extra etc/ssh")
	}

	log.Debug().Str("machine", machine).Msg("decrypting host SSH key for extra files")
	privPEM, err := sops.DecryptBinary(srcPriv)
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

func decryptZFSKey(cfg *Config, machine string) (string, error) {
	log.Debug().Str("machine", machine).Msg("decrypting ZFS root key")
	key, err := sops.DecryptYAMLExtract(
		filepath.Join(cfg.FlakeDir, "machines", machine, "secrets.yaml"),
		"zfs-root-key",
	)
	if err != nil {
		return "", errors.Wrapf(err, "decrypt zfs-root-key for %s", machine)
	}
	f, err := os.CreateTemp("", "deploy-zfskey-*")
	if err != nil {
		return "", errors.Wrap(err, "create zfs key tmpfile")
	}
	defer f.Close()
	if _, err := fmt.Fprint(f, key); err != nil {
		return "", errors.Wrap(err, "write zfs key")
	}
	if err := os.Chmod(f.Name(), 0o400); err != nil {
		return "", errors.Wrap(err, "chmod zfs key file")
	}
	return f.Name(), nil
}

func prepareInitrdKeys(cfg *Config, machine, extraDir string) error {
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
		localSecret := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "initrd-ssh", localKey)
		if !fileExists(localSecret) {
			return errors.Errorf("missing initrd SSH key for %s: %s", hostKeyPath, localSecret)
		}
		log.Debug().Str("key", hostKeyPath).Msg("decrypting initrd host key")
		privPEM, err := sops.DecryptBinary(localSecret)
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

func uploadOpenSSHHostKey(cfg *Config, machine, targetHost string, sshArgs []string) error {
	const hostKeyPath = "/etc/ssh/ssh_host_ed25519_key"

	localPublic := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "openssh", "ssh_host_ed25519_key.pub")
	localSecret := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "openssh", "ssh_host_ed25519_key")
	if !fileExists(localSecret) {
		return errors.Errorf("missing OpenSSH host key %s", localSecret)
	}
	if !fileExists(localPublic) {
		return errors.Errorf("missing OpenSSH host public key %s", localPublic)
	}

	pubLine, err := os.ReadFile(localPublic)
	if err != nil {
		return errors.Wrapf(err, "read OpenSSH host public key %s", localPublic)
	}

	log.Info().Str("path", hostKeyPath).Msg("checking remote OpenSSH host key")
	matches, err := remoteKeyMatches(targetHost, sshArgs, hostKeyPath, pubLine, "OpenSSH host key")
	if err != nil {
		return err
	}
	if matches {
		log.Info().Str("path", hostKeyPath).Msg("remote OpenSSH host key already matches; skipping decrypt/upload")
		return nil
	}

	log.Info().Str("path", hostKeyPath).Msg("remote OpenSSH host key differs or is missing; decrypting local key")
	privPEM, err := sops.DecryptBinary(localSecret)
	if err != nil {
		return errors.Wrapf(err, "decrypt OpenSSH host key %s", localSecret)
	}

	log.Info().Str("path", hostKeyPath).Msg("uploading OpenSSH host key")
	return uploadPrivateKey(targetHost, sshArgs, hostKeyPath, privPEM)
}

func uploadInitrdKeys(cfg *Config, machine, targetHost string, sshArgs []string) error {
	raw, err := nix.Eval(cfg.FlakeDir, cfg.MachineAttr(machine, "config.boot.initrd.network.ssh.hostKeys"))
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
		localPublic := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "initrd-ssh", localKey+".pub")
		localSecret := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "initrd-ssh", localKey)
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
			log.Info().Str("path", hostKeyPath).Msg("remote initrd host key already matches; skipping decrypt/upload")
			continue
		}

		log.Info().Str("path", hostKeyPath).Msg("remote initrd host key differs or is missing; decrypting local key")
		privPEM, err := sops.DecryptBinary(localSecret)
		if err != nil {
			return errors.Wrapf(err, "decrypt initrd key %s", localSecret)
		}

		log.Info().Str("path", hostKeyPath).Msg("uploading initrd host key")
		if err := uploadPrivateKey(sshTarget, sshArgs, hostKeyPath, privPEM); err != nil {
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

func uploadPrivateKey(targetHost string, sshArgs []string, hostKeyPath string, privPEM []byte) error {
	remoteCmd := fmt.Sprintf(
		"mkdir -p '%s' && umask 077 && cat > '%s.tmp' && mv '%s.tmp' '%s'",
		filepath.Dir(hostKeyPath), hostKeyPath, hostKeyPath, hostKeyPath,
	)
	runArgs := append(append([]string{}, sshArgs...), targetHost, remoteCmd)
	cmd := exec.Command("ssh", runArgs...)
	cmd.Stdin = bytes.NewReader(privPEM)
	cmd.Stderr = os.Stderr
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
