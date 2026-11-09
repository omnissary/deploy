// Package installer describes installation backends independently of filesystem
// and transport. Preparation stays in the machine service; invocation is data.
package installer

import (
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
)

type Invocation struct {
	Program   string
	Arguments []string
}
type Prepared struct {
	Artifact  string
	Arguments []string
}
type Backend interface {
	Validate(manifest.Machine) error
	Artifacts(manifest.Machine) []string
	SecretDelivery() string
	Command(Prepared) (Invocation, error)
}
type Registry map[string]Backend

func NewRegistry() Registry {
	return Registry{"nixos-anywhere": Anywhere{}, "executable": Executable{}}
}

func (r Registry) Resolve(name string) (Backend, error) {
	b, ok := r[name]
	if !ok {
		return nil, errors.Errorf("unsupported installation backend %q; build/deploy remain available", name)
	}
	return b, nil
}

type Anywhere struct{}

func (Anywhere) Validate(m manifest.Machine) error {
	if !m.Disko {
		return errors.New("nixos-anywhere requires a declared diskoScript")
	}
	return nil
}

func (Anywhere) Artifacts(manifest.Machine) []string {
	return []string{"config.system.build.toplevel", "config.system.build.diskoScript"}
}
func (Anywhere) SecretDelivery() string { return "staged-files" }
func (Anywhere) Command(p Prepared) (Invocation, error) {
	return Invocation{Program: "nixos-anywhere", Arguments: p.Arguments}, nil
}

type Executable struct{}

func (Executable) Validate(m manifest.Machine) error {
	if !strings.HasPrefix(m.Installer.Attribute, "config.system.build.") {
		return errors.New("executable installer requires a config.system.build artifact")
	}
	return nil
}
func (Executable) Artifacts(m manifest.Machine) []string { return []string{m.Installer.Attribute} }
func (Executable) SecretDelivery() string                { return "out-of-band" }
func (Executable) Command(p Prepared) (Invocation, error) {
	if p.Artifact == "" {
		return Invocation{}, errors.New("installer artifact not built")
	}
	return Invocation{Program: p.Artifact}, nil
}
