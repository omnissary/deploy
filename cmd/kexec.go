package cmd

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/nix"
	"git.tatikoma.dev/corpix/deploy/internal/sshkey"
)

func kexecCmd() *cli.Command {
	return &cli.Command{
		Name:  "kexec",
		Usage: "build and manage kexec installer images",
		Before: func(ctx *cli.Context) error {
			return requireFlake(getConfig(ctx))
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "flavor",
				Usage: "kexec image flavor: zfs or ext4",
				Value: "zfs",
			},
		},
		Action: func(ctx *cli.Context) error {
			cfg := getConfig(ctx)
			flavor := ctx.String("flavor")
			attr := "tiny-kexec-" + flavor
			log.Info().Str("flavor", flavor).Str("attr", attr).Msg("building kexec image")
			path, err := nix.Build(cfg.FlakeDir, attr)
			if err != nil {
				return errors.Wrapf(err, "build kexec %s", flavor)
			}
			log.Info().Str("path", path).Msg("kexec image built")
			return nil
		},
		Subcommands: []*cli.Command{
			{
				Name:  "debug",
				Usage: "extract the kexec image and boot it in QEMU (C-a x to exit)",
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					return kexecDebug(cfg)
				},
			},
		},
	}
}

func kexecDebug(cfg *Config) error {
	tarball := filepath.Join(cfg.FlakeDir, "result", "nixos-kexec-installer-x86_64-linux.tar.gz")
	if _, err := os.Stat(tarball); err != nil {
		return errors.Errorf("kexec tarball not found at %s; run 'deploy kexec' first", tarball)
	}

	root, err := os.MkdirTemp("", "kexec-ext-*")
	if err != nil {
		return errors.Wrap(err, "create kexec extract dir")
	}
	defer func() { _ = os.RemoveAll(root) }()

	log.Debug().Str("dir", root).Msg("extracting kexec tarball")
	if err := extractTarGz(tarball, root); err != nil {
		return errors.Wrapf(err, "extract kexec tarball")
	}

	// Parse init and kernelParams from kexec/run.
	runPath := filepath.Join(root, "kexec", "run")
	initPath, kernelParams, err := parseKexecRun(runPath)
	if err != nil {
		return errors.Wrapf(err, "parse kexec/run")
	}
	log.Debug().Str("init", initPath).Str("params", kernelParams).Msg("kexec params")

	// Build the inject cpio payload: synthetic SSH host key + empty network JSON.
	injectDir, err := os.MkdirTemp("", "kexec-inject-*")
	if err != nil {
		return errors.Wrap(err, "create inject dir")
	}
	defer func() { _ = os.RemoveAll(injectDir) }()

	if err := buildInjectDir(injectDir); err != nil {
		return errors.Wrapf(err, "build inject dir")
	}

	// Append the cpio payload (gzip-compressed) to the initrd.
	initrd := filepath.Join(root, "kexec", "initrd")
	if err := os.Chmod(initrd, 0o644); err != nil {
		return errors.Wrapf(err, "chmod initrd")
	}
	if err := appendCpioToInitrd(injectDir, initrd); err != nil {
		return errors.Wrapf(err, "append cpio to initrd")
	}

	qemu, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return errors.Wrap(err, "find qemu-system-x86_64")
	}

	kernel := filepath.Join(root, "kexec", "bzImage")
	args := []string{
		"qemu-system-x86_64",
		"-enable-kvm",
		"-m", "957M",
		"-nographic",
		"-netdev", "user,id=n1,hostfwd=tcp::2222-:22",
		"-device", "virtio-net-pci,netdev=n1",
		"-kernel", kernel,
		"-initrd", initrd,
		"-append", "init=" + initPath + " " + kernelParams,
	}

	log.Info().Msg("booting kexec image in QEMU — press C-a x to exit")
	return syscall.Exec(qemu, args, os.Environ())
}

var (
	reInit   = regexp.MustCompile(`^init="(.*)"`)
	reParams = regexp.MustCompile(`^kernelParams="(.*)"`)
)

func parseKexecRun(path string) (initPath, kernelParams string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", errors.Wrapf(err, "open %s", path)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if m := reInit.FindStringSubmatch(line); m != nil {
			initPath = m[1]
		}
		if m := reParams.FindStringSubmatch(line); m != nil {
			kernelParams = m[1]
		}
	}
	if err := s.Err(); err != nil {
		return "", "", errors.Wrap(err, "scan kexec/run")
	}
	if initPath == "" {
		return "", "", errors.New("init not found in kexec/run")
	}
	return initPath, kernelParams, nil
}

func buildInjectDir(dir string) error {
	sshDir := filepath.Join(dir, "ssh")
	if err := os.MkdirAll(sshDir, 0o755); err != nil {
		return errors.Wrap(err, "create inject ssh dir")
	}

	pair, err := sshkey.Generate()
	if err != nil {
		return err
	}
	privPEM, err := sshkey.MarshalPrivatePEM(pair)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(sshDir, "ssh_host_ed25519_key"), privPEM, 0o600); err != nil {
		return errors.Wrap(err, "write inject host key")
	}

	pubLine, err := sshkey.MarshalPublicAuthorizedKey(pair, "")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(sshDir, "ssh_host_ed25519_key.pub"), pubLine, 0o644); err != nil {
		return errors.Wrap(err, "write inject host pub key")
	}

	for _, name := range []string{"addrs.json", "routes-v4.json", "routes-v6.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("[]\n"), 0o644); err != nil {
			return errors.Wrapf(err, "write inject %s", name)
		}
	}
	return nil
}

func appendCpioToInitrd(injectDir, initrdPath string) error {
	f, err := os.OpenFile(initrdPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return errors.Wrapf(err, "open initrd %s for append", initrdPath)
	}
	defer f.Close()

	gw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return errors.Wrap(err, "create gzip writer")
	}
	defer gw.Close()

	// Shell out to cpio since there's no stdlib support for newc cpio.
	findCmd := exec.Command("find", ".")
	findCmd.Dir = injectDir
	findOut, err := findCmd.Output()
	if err != nil {
		return errors.Wrap(err, "find inject files")
	}

	cpioCmd := exec.Command("cpio", "-o", "-H", "newc")
	cpioCmd.Dir = injectDir
	cpioCmd.Stdin = strings.NewReader(string(findOut))
	cpioCmd.Stdout = gw
	var cpioErr strings.Builder
	cpioCmd.Stderr = &cpioErr
	if err := cpioCmd.Run(); err != nil {
		return errors.Wrapf(err, "cpio: %s", cpioErr.String())
	}
	return nil
}

func extractTarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return errors.Wrapf(err, "open %s", src)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return errors.Wrap(err, "gzip reader")
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "tar next")
		}

		// Sanitise path to prevent path traversal.
		target := filepath.Join(dst, filepath.Clean("/"+hdr.Name))
		if !strings.HasPrefix(target, dst) {
			return errors.Errorf("tar path traversal: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return errors.Wrapf(err, "mkdir %s", target)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return errors.Wrapf(err, "mkdir parent %s", target)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return errors.Wrapf(err, "create %s", target)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return errors.Wrapf(err, "write %s", target)
			}
			out.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, target); err != nil && !os.IsExist(err) {
				return errors.Wrapf(err, "symlink %s -> %s", target, hdr.Linkname)
			}
		}
	}
	return nil
}
