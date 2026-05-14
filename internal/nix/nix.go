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
	buildCores   string
	maxJobs      string
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

// SetConfig configures default Nix parallelism limits for subprocesses.
func SetConfig(cores, jobs string) {
	buildCores = strings.TrimSpace(cores)
	maxJobs = strings.TrimSpace(jobs)
}

func makeEnv(cores, jobs string) []string {
	env := os.Environ()
	var config []string
	if cores != "" {
		config = append(config, "cores = "+cores)
	}
	if jobs != "" {
		config = append(config, "max-jobs = "+jobs)
	}
	if len(config) == 0 {
		return env
	}
	return append(env, "NIX_CONFIG="+strings.Join(config, "\n"))
}

func commandEnv() []string {
	return makeEnv(buildCores, maxJobs)
}

// Client runs nix subprocesses with its own output writers.
// BuildCores and MaxJobs are read from the global SetConfig values at call time.
type Client struct {
	stdout io.Writer
	stderr io.Writer
}

// NewClient returns a Client that writes subprocess output to the given writers.
func NewClient(stdout, stderr io.Writer) *Client {
	return &Client{stdout: stdout, stderr: stderr}
}

func (c *Client) commandEnv() []string {
	return makeEnv(buildCores, maxJobs)
}

func (c *Client) run(args ...string) ([]byte, error) {
	return c.runStdin(nil, args...)
}

func (c *Client) runStdin(stdin io.Reader, args ...string) ([]byte, error) {
	log.Debug().Strs("args", args).Msg("nix")
	cmd := exec.Command("nix", args...)
	cmd.Env = c.commandEnv()
	cmd.Stderr = c.stderr
	cmd.Stdin = stdin
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "nix %s", strings.Join(args, " "))
	}
	return out, nil
}

// Build builds a nix attribute and returns the store path.
func (c *Client) Build(flake, attr string) (string, error) {
	return Build(flake, attr)
}

// Eval evaluates a nix attribute and returns raw JSON bytes.
func (c *Client) Eval(flake, attr string) (json.RawMessage, error) {
	return Eval(flake, attr)
}

// EvalApply evaluates a nix attribute with an apply function and returns raw JSON bytes.
func (c *Client) EvalApply(flake, attr, apply string) (json.RawMessage, error) {
	return EvalApply(flake, attr, apply)
}

// Copy copies a store path to an SSH remote using NIX_SSHOPTS.
func (c *Client) Copy(storePath, sshURL string, sshOpts []string) error {
	return Copy(storePath, sshURL, sshOpts)
}

// --- package-level functions backed by global writers ---

func run(args ...string) ([]byte, error) {
	return runStdin(nil, args...)
}

func runStdin(stdin io.Reader, args ...string) ([]byte, error) {
	log.Debug().Strs("args", args).Msg("nix")
	cmd := exec.Command("nix", args...)
	cmd.Env = commandEnv()
	cmd.Stderr = stderrWriter
	cmd.Stdin = stdin
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

// EvalApply evaluates a nix attribute with an apply function and returns raw JSON bytes.
func EvalApply(flake, attr, apply string) (json.RawMessage, error) {
	ref := flake + "#" + attr
	log.Debug().
		Str("flake", flake).Str("ref", ref).
		Str("apply", apply).
		Msg("nix eval")
	out, err := run("eval", "--json", "--apply", apply, ref)
	if err != nil {
		return nil, errors.Wrapf(err, "eval %s#%s", flake, attr)
	}
	return json.RawMessage(bytes.TrimSpace(out)), nil
}

// Copy copies a store path to an SSH remote using NIX_SSHOPTS.
func Copy(storePath, sshURL string, sshOpts []string) error {
	log.Debug().Str("path", storePath).Str("to", sshURL).Msg("nix copy")
	cmd := exec.Command("nix", "copy", "--log-format", "bar-with-logs", "--to", sshURL, storePath)
	cmd.Env = commandEnv()
	if len(sshOpts) > 0 {
		cmd.Env = append(cmd.Env, "NIX_SSHOPTS="+strings.Join(sshOpts, " "))
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
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
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
	cmd.Env = commandEnv()
	cmd.Stdout = stdoutWriter
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "why-depends %s %s: %s", path, dep, stderr.String())
	}
	return nil
}
