// Package manifest defines deploy's versioned, public Nix metadata contract.
package manifest

import (
	_ "embed"
	"encoding/json"
	"path/filepath"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
)

//go:embed resolve.nix
var Expression string

const Version = 1

type Manifest struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Machines      map[string]Machine     `json:"machines"`
	Authorities   map[string]Authority   `json:"authorities"`
	Certificates  map[string]Certificate `json:"certificates"`
	Trust         map[string][]string    `json:"trust"`
}
type Machine struct {
	System              string            `json:"system"`
	HostKey             bool              `json:"hostKey"`
	InitrdSSH           bool              `json:"initrdSSH"`
	InitrdPort          int               `json:"initrdPort"`
	Disko               bool              `json:"disko"`
	Installer           Installer         `json:"installer"`
	Unlock              string            `json:"unlock"`
	Pools               map[string]Pool   `json:"pools"`
	Groups              []string          `json:"groups"`
	Addresses           map[string]string `json:"addresses"`
	Yggdrasil           bool              `json:"yggdrasil"`
	YggdrasilAddressTag string            `json:"yggdrasilAddressTag"`
	Certificates        []string          `json:"certificates"`
	Source              string            `json:"source,omitempty"`
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
	Group bool   `json:"group"`
	Cert  string `json:"cert"`
	Key   string `json:"key"`
	Chain string `json:"chain"`
	CA    string `json:"ca"`
}
type Authority struct {
	PolicySource   string   `json:"policySource,omitempty"`
	Issuer         string   `json:"issuer"`
	Subject        string   `json:"subject"`
	Algorithm      string   `json:"algorithm"`
	ValidityDays   int      `json:"validityDays"`
	PathLen        *int     `json:"pathLen,omitempty"`
	DNSConstraints []string `json:"dnsConstraints"`
	Source         *Target  `json:"source,omitempty"`
}
type Extension struct {
	OID      string  `json:"oid"`
	Critical bool    `json:"critical"`
	DER      string  `json:"der"`
	UTF8     *string `json:"utf8,omitempty"`
}
type Certificate struct {
	PolicySource    string      `json:"policySource,omitempty"`
	Issuer          string      `json:"issuer"`
	Subject         string      `json:"subject"`
	Organization    string      `json:"organization"`
	UID             string      `json:"uid"`
	DNS             []string    `json:"dns"`
	IP              []string    `json:"ip"`
	Email           []string    `json:"email"`
	URI             []string    `json:"uri"`
	Usage           []string    `json:"usage"`
	Algorithm       string      `json:"algorithm"`
	ValidityDays    int         `json:"validityDays"`
	RenewBeforeDays int         `json:"renewBeforeDays"`
	Extensions      []Extension `json:"extensions"`
	Target          Target      `json:"target"`
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
