// Package manifest defines deploy's versioned, public Nix metadata contract.
package manifest

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
	"git.tatikoma.dev/corpix/deploy/nix"
)

var Expression = nix.ManifestExpression

const Version = 2

type Manifest struct {
	Machines      map[string]Machine     `json:"machines"`
	Authorities   map[string]Authority   `json:"authorities"`
	Certificates  map[string]Certificate `json:"certificates"`
	Trust         map[string][]string    `json:"trust"`
	SchemaVersion int                    `json:"schemaVersion"`
}
type SecretRef struct {
	Name  string `json:"name"`
	Key   string `json:"key"`
	Group bool   `json:"group"`
}
type Machine struct {
	Pools           map[string]Pool `json:"pools"`
	Installer       Installer       `json:"installer"`
	RootFS          string          `json:"rootFS"`
	System          string          `json:"system"`
	Unlock          string          `json:"unlock"`
	RequiredSecrets []SecretRef     `json:"requiredSecrets"`
	InitrdPort      int             `json:"initrdPort"`
	HostKey         bool            `json:"hostKey"`
	InitrdSSH       bool            `json:"initrdSSH"`
}
type Installer struct {
	Backend   string `json:"backend"`
	Attribute string `json:"attribute"`
}
type Pool struct {
	KeyPath  string   `json:"keyPath"`
	Secret   string   `json:"secret"`
	Format   string   `json:"format"`
	Datasets []string `json:"datasets"`
}
type Target struct {
	Name  string `json:"name"`
	Cert  string `json:"cert"`
	Key   string `json:"key"`
	Chain string `json:"chain"`
	CA    string `json:"ca"`
	Group bool   `json:"group"`
}

func (t Target) Validate() error {
	roles := map[string]string{}
	for _, role := range []struct{ name, key string }{
		{"cert", t.Cert},
		{"key", t.Key},
		{"chain", t.Chain},
		{"ca", t.CA},
	} {
		if role.key == "" {
			continue
		}
		if previous, ok := roles[role.key]; ok {
			return errors.Errorf("target key %s is used for both %s and %s", role.key, previous, role.name)
		}
		roles[role.key] = role.name
	}
	return nil
}

type Authority struct {
	Target         *Target  `json:"target,omitempty"`
	PathLen        *int     `json:"pathLen,omitempty"`
	PolicySource   string   `json:"policySource,omitempty"`
	Issuer         string   `json:"issuer"`
	Subject        string   `json:"subject"`
	Algorithm      string   `json:"algorithm"`
	DNSConstraints []string `json:"dnsConstraints"`
	ValidityDays   int      `json:"validityDays"`
}
type Extension struct {
	UTF8     *string `json:"utf8,omitempty"`
	OID      string  `json:"oid"`
	DER      string  `json:"der"`
	Critical bool    `json:"critical"`
}
type Certificate struct {
	Target          Target      `json:"target"`
	PolicySource    string      `json:"policySource,omitempty"`
	Issuer          string      `json:"issuer"`
	Subject         string      `json:"subject"`
	Organization    string      `json:"organization"`
	UID             string      `json:"uid"`
	Algorithm       string      `json:"algorithm"`
	KeyUsage        []string    `json:"keyUsage"`
	DNS             []string    `json:"dns"`
	IP              []string    `json:"ip"`
	Email           []string    `json:"email"`
	URI             []string    `json:"uri"`
	Usage           []string    `json:"usage"`
	Extensions      []Extension `json:"extensions"`
	ValidityDays    int         `json:"validityDays"`
	RenewBeforeDays int         `json:"renewBeforeDays"`
}

func Decode(data []byte) (Manifest, error) {
	var m Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return m, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return m, errors.New("expected one deploy policy document")
	}
	if m.SchemaVersion != Version {
		return m, errors.Errorf("unsupported deploy schemaVersion %d (supported: %d)", m.SchemaVersion, Version)
	}
	for name, v := range m.Machines {
		if !vars.ValidName(name) || v.System == "" {
			return m, errors.Errorf("machine %s requires a valid name and explicit system", name)
		}
		if v.InitrdPort == 0 {
			v.InitrdPort = 2222
		}
		if v.InitrdPort < 1 || v.InitrdPort > 65535 {
			return m, errors.Errorf("invalid initrdPort for %s", name)
		}
		switch v.Unlock {
		case "":
		case "zfs", "luks":
			if !v.InitrdSSH {
				return m, errors.Errorf("unlock for %s requires initrdSSH", name)
			}
			if v.Unlock == "zfs" && len(v.Pools) == 0 {
				return m, errors.Errorf("ZFS unlock for %s requires pools", name)
			}
		default:
			return m, errors.Errorf("unsupported unlock backend %q", v.Unlock)
		}
		switch v.Installer.Backend {
		case "", "nixos-anywhere":
			if v.Installer.Attribute != "" {
				return m, errors.New("installer attribute requires executable backend")
			}
		case "executable":
			if !strings.HasPrefix(v.Installer.Attribute, "config.system.build.") {
				return m, errors.New("executable installer requires a config.system.build artifact")
			}
		default:
			return m, errors.Errorf("unsupported installer backend %q", v.Installer.Backend)
		}
		for pool, p := range v.Pools {
			if !vars.ValidName(pool) || p.Secret == "" {
				return m, errors.Errorf("pool %s/%s requires an explicit secret", name, pool)
			}
			if !filepath.IsAbs(p.KeyPath) || strings.ContainsAny(p.KeyPath, "\x00\r\n") {
				return m, errors.Errorf("invalid keyPath for %s/%s", name, pool)
			}
			switch p.Format {
			case "", "hex", "passphrase":
			default:
				return m, errors.Errorf("unsupported key format for %s/%s", name, pool)
			}
		}
		for _, secret := range v.RequiredSecrets {
			if !vars.ValidName(secret.Name) || secret.Key == "" {
				return m, errors.Errorf("invalid required secret for %s", name)
			}
		}
		m.Machines[name] = v
	}
	for name, spec := range m.Certificates {
		if err := spec.Target.Validate(); err != nil {
			return m, errors.Wrapf(err, "certificate %s", name)
		}
		spec.PolicySource = "nix"
		m.Certificates[name] = spec
	}
	for name, spec := range m.Authorities {
		if spec.Target != nil {
			if err := spec.Target.Validate(); err != nil {
				return m, errors.Wrapf(err, "authority %s", name)
			}
		}
		spec.PolicySource = "nix"
		m.Authorities[name] = spec
	}
	return m, nil
}
