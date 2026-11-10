// Package manifest defines deploy's versioned, public Nix metadata contract.
package manifest

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/nix"
)

var Expression = nix.ManifestExpression

const Version = 1

type Manifest struct {
	Machines      map[string]Machine     `json:"machines"`
	Authorities   map[string]Authority   `json:"authorities"`
	Certificates  map[string]Certificate `json:"certificates"`
	Trust         map[string][]string    `json:"trust"`
	SchemaVersion int                    `json:"schemaVersion"`
}
type Machine struct {
	Pools               map[string]Pool   `json:"pools"`
	Addresses           map[string]string `json:"addresses"`
	Installer           Installer         `json:"installer"`
	RootFS              string            `json:"rootFS"`
	System              string            `json:"system"`
	Unlock              string            `json:"unlock"`
	YggdrasilAddressTag string            `json:"yggdrasilAddressTag"`
	Source              string            `json:"source,omitempty"`
	Groups              []string          `json:"groups"`
	Certificates        []string          `json:"certificates"`
	InitrdPort          int               `json:"initrdPort"`
	HostKey             bool              `json:"hostKey"`
	InitrdSSH           bool              `json:"initrdSSH"`
	Disko               bool              `json:"disko"`
	Yggdrasil           bool              `json:"yggdrasil"`
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
type Authority struct {
	Target         *Target  `json:"target,omitempty"`
	PathLen        *int     `json:"pathLen,omitempty"`
	Source         *Target  `json:"source,omitempty"`
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
	if err := json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	if m.SchemaVersion != Version {
		return m, errors.Errorf("unsupported deploy schemaVersion %d (supported: %d)", m.SchemaVersion, Version)
	}
	for name, v := range m.Machines {
		if v.InitrdPort == 0 {
			v.InitrdPort = 2222
		}
		for pool, p := range v.Pools {
			if p.Secret == "" {
				p.Secret = pool + "-root-key"
			}
			if p.Format == "" {
				p.Format = "hex"
			}
			if !filepath.IsAbs(p.KeyPath) || strings.ContainsAny(p.KeyPath, "\x00\r\n") {
				return m, errors.Errorf("invalid keyPath for %s/%s", name, pool)
			}
			v.Pools[pool] = p
		}
		if v.Installer.Backend == "" && v.Disko {
			v.Installer.Backend = "nixos-anywhere"
		}
		if v.Unlock == "" && len(v.Pools) > 0 {
			v.Unlock = "zfs"
		}
		m.Machines[name] = v
	}
	for name, spec := range m.Certificates {
		spec.PolicySource = "nix"
		m.Certificates[name] = spec
	}
	for name, spec := range m.Authorities {
		spec.PolicySource = "nix"
		m.Authorities[name] = spec
	}
	return m, nil
}
