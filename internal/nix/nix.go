package nix

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
)

var (
	stdoutWriter io.Writer = os.Stdout
	stderrWriter io.Writer = os.Stderr
)

// SetWriters configures where nix subprocess output is streamed.
func SetWriters(stdout, stderr io.Writer) {
	if stdout != nil {
		stdoutWriter = stdout
	}
	if stderr != nil {
		stderrWriter = stderr
	}
}

func run(args ...string) ([]byte, error) {
	log.Debug().Strs("args", args).Msg("nix")
	cmd := exec.Command("nix", args...)
	cmd.Stderr = stderrWriter
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "nix %s", strings.Join(args, " "))
	}
	return out, nil
}

// Build builds a nix attribute and returns the store path.
func Build(flake, attr string) (string, error) {
	ref := flake + "#" + attr
	log.Debug().Str("ref", ref).Msg("nix build")
	out, err := run("build", "--no-link", "--print-out-paths", ref)
	if err != nil {
		return "", errors.Wrapf(err, "build %s", ref)
	}
	return strings.TrimSpace(string(out)), nil
}

// Eval evaluates a nix attribute and returns raw JSON bytes.
func Eval(flake, attr string) (json.RawMessage, error) {
	ref := flake + "#" + attr
	log.Debug().Str("ref", ref).Msg("nix eval")
	out, err := run("eval", "--json", ref)
	if err != nil {
		return nil, errors.Wrapf(err, "eval %s", ref)
	}
	return json.RawMessage(bytes.TrimSpace(out)), nil
}

// Copy copies a store path to an SSH remote using NIX_SSHOPTS.
func Copy(storePath, sshURL string, sshOpts []string) error {
	log.Debug().Str("path", storePath).Str("to", sshURL).Msg("nix copy")
	cmd := exec.Command("nix", "copy", "--log-format", "bar-with-logs", "--to", sshURL, storePath)
	if len(sshOpts) > 0 {
		cmd.Env = append(cmd.Environ(), "NIX_SSHOPTS="+strings.Join(sshOpts, " "))
	}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "nix copy to %s", sshURL)
	}
	return nil
}

// PathInfo returns all store paths reachable from the given path (nix path-info -r).
func PathInfo(storePath string) ([]string, error) {
	log.Debug().Str("path", storePath).Msg("nix path-info")
	out, err := run("path-info", "-r", storePath)
	if err != nil {
		return nil, errors.Wrapf(err, "path-info %s", storePath)
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths, nil
}

// WhyDepends prints why path depends on dep to stdout.
func WhyDepends(path, dep string) error {
	log.Debug().Str("path", path).Str("dep", dep).Msg("nix why-depends")
	cmd := exec.Command("nix", "why-depends", path, dep)
	cmd.Stdout = stdoutWriter
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "why-depends %s %s: %s", path, dep, stderr.String())
	}
	return nil
}
