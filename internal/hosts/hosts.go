// Package hosts manages the per-flake registry that maps machine names to
// network addresses and declares machine groups (named sets of machines that
// share SOPS-encrypted secret files).
//
// On-disk format:
//
//	addresses:
//	  alexandria: 10.94.10.1          # plain address, used for any operation
//	  ares:
//	    ssh: 200:dffb::1              # used by machine ssh / deploy
//	    unlock: 5.6.7.8              # used by machine unlock
//	    default: 200:dffb::1         # optional fallback for untagged operations
//	groups:
//	  loki-ca: [alexandria, ares]
//
// A flat legacy format (machine: addr at top level) is still read for backward
// compatibility but is rewritten into the structured form on the next save.
package hosts

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"gopkg.in/yaml.v3"

	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
)

// AddressEntry holds either a plain address (Default) or per-operation tagged
// addresses, or both. A plain YAML scalar unmarshals into Default; a mapping
// unmarshals into Tags (with an optional "default" key populating Default).
type AddressEntry struct {
	Default string
	Tags    map[string]string
}

// Get returns the address for the given operation tag. If the tag is not found
// in Tags, Default is returned.
func (e *AddressEntry) Get(tag string) string {
	if e == nil {
		return ""
	}
	if tag != "" {
		if addr, ok := e.Tags[tag]; ok {
			return addr
		}
	}
	return e.Default
}

func (e *AddressEntry) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		return value.Decode(&e.Default)
	case yaml.MappingNode:
		var m map[string]string
		if err := value.Decode(&m); err != nil {
			return err
		}
		e.Default = m["default"]
		delete(m, "default")
		e.Tags = m
		return nil
	default:
		return fmt.Errorf("address: unexpected YAML node kind %v", value.Kind)
	}
}

func (e AddressEntry) MarshalYAML() (interface{}, error) {
	if len(e.Tags) == 0 {
		return e.Default, nil
	}
	m := make(map[string]string, len(e.Tags)+1)
	for k, v := range e.Tags {
		m[k] = v
	}
	if e.Default != "" {
		m["default"] = e.Default
	}
	return m, nil
}

// File is the parsed contents of the hosts registry.
type File struct {
	Addresses map[string]*AddressEntry `yaml:"addresses,omitempty"`
	Groups    map[string][]string      `yaml:"groups,omitempty"`
}

// Load reads and parses the hosts file. Missing files are treated as empty.
// Accepts the structured format, a tagged-address format, and the legacy flat
// machine:addr map.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return empty(), nil
		}
		return nil, errors.Wrapf(err, "read hosts file %s", path)
	}

	var structured File
	if err := yaml.Unmarshal(data, &structured); err == nil {
		if structured.Addresses != nil || structured.Groups != nil {
			return normalize(&structured), nil
		}
	}

	var legacy map[string]string
	if err := yaml.Unmarshal(data, &legacy); err != nil {
		return nil, errors.Wrapf(err, "parse hosts file %s", path)
	}
	addrs := make(map[string]*AddressEntry, len(legacy))
	for k, v := range legacy {
		addrs[k] = &AddressEntry{Default: v}
	}
	return normalize(&File{Addresses: addrs}), nil
}

// Save writes the hosts file atomically with stable, sorted output.
func Save(path string, f *File) error {
	f = normalize(f)
	data, err := yaml.Marshal(f)
	if err != nil {
		return errors.Wrap(err, "marshal hosts")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Wrapf(err, "create hosts dir")
	}
	return atomicfile.Write(path, data, 0o644)
}

// GetAddress returns the address for a machine and operation tag. If tag is
// empty or not present in the machine's tag map, the plain default address is
// returned. Returns an empty string when no address is registered.
func GetAddress(path, machine, tag string) (string, error) {
	f, err := Load(path)
	if err != nil {
		return "", err
	}
	return f.Addresses[machine].Get(tag), nil
}

// SetAddress registers or updates an address for a machine. Pass an empty tag
// to set the plain default address; pass a tag name to set an operation-specific
// address.
func SetAddress(path, machine, tag, addr string) error {
	log.Debug().Str("machine", machine).Str("tag", tag).Str("addr", addr).Str("file", path).Msg("setting address")
	f, err := Load(path)
	if err != nil {
		return err
	}
	entry := f.Addresses[machine]
	if entry == nil {
		entry = &AddressEntry{}
		f.Addresses[machine] = entry
	}
	if tag == "" {
		entry.Default = addr
	} else {
		if entry.Tags == nil {
			entry.Tags = map[string]string{}
		}
		entry.Tags[tag] = addr
	}
	return Save(path, f)
}

// HasAddress reports whether the named machine has any registered address.
func HasAddress(path, machine string) (bool, error) {
	f, err := Load(path)
	if err != nil {
		return false, err
	}
	entry := f.Addresses[machine]
	return entry != nil && (entry.Default != "" || len(entry.Tags) > 0), nil
}

// Groups returns a deep copy of all declared groups.
func Groups(path string) (map[string][]string, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(f.Groups))
	for name, members := range f.Groups {
		out[name] = append([]string(nil), members...)
	}
	return out, nil
}

// GroupMembers returns a copy of one group's members, or an error if the
// group is not declared.
func GroupMembers(path, group string) ([]string, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	members, ok := f.Groups[group]
	if !ok {
		return nil, errors.Errorf("group %q not found", group)
	}
	return append([]string(nil), members...), nil
}

// HasGroup reports whether the named group is declared.
func HasGroup(path, group string) (bool, error) {
	f, err := Load(path)
	if err != nil {
		return false, err
	}
	_, ok := f.Groups[group]
	return ok, nil
}

// CreateGroup creates an empty group. Errors if it already exists.
func CreateGroup(path, group string, members []string) error {
	f, err := Load(path)
	if err != nil {
		return err
	}
	if _, ok := f.Groups[group]; ok {
		return errors.Errorf("group %q already exists", group)
	}
	f.Groups[group] = uniqueSorted(members)
	return Save(path, f)
}

// AddMembers adds machines to a group, creating it if missing.
// Returns the resulting member list.
func AddMembers(path, group string, machines []string) ([]string, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	merged := uniqueSorted(append(f.Groups[group], machines...))
	f.Groups[group] = merged
	if err := Save(path, f); err != nil {
		return nil, err
	}
	return merged, nil
}

// RemoveMembers removes machines from a group. Errors if the group is not
// declared. Returns the resulting member list.
func RemoveMembers(path, group string, machines []string) ([]string, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	current, ok := f.Groups[group]
	if !ok {
		return nil, errors.Errorf("group %q not found", group)
	}
	drop := map[string]struct{}{}
	for _, m := range machines {
		drop[m] = struct{}{}
	}
	filtered := current[:0:0]
	for _, m := range current {
		if _, removed := drop[m]; removed {
			continue
		}
		filtered = append(filtered, m)
	}
	f.Groups[group] = filtered
	if err := Save(path, f); err != nil {
		return nil, err
	}
	return filtered, nil
}

// DeleteGroup removes a group from the file. Errors if the group is not
// declared.
func DeleteGroup(path, group string) error {
	f, err := Load(path)
	if err != nil {
		return err
	}
	if _, ok := f.Groups[group]; !ok {
		return errors.Errorf("group %q not found", group)
	}
	delete(f.Groups, group)
	return Save(path, f)
}

func empty() *File {
	return &File{
		Addresses: map[string]*AddressEntry{},
		Groups:    map[string][]string{},
	}
}

func normalize(f *File) *File {
	if f == nil {
		return empty()
	}
	if f.Addresses == nil {
		f.Addresses = map[string]*AddressEntry{}
	}
	if f.Groups == nil {
		f.Groups = map[string][]string{}
	}
	for name, members := range f.Groups {
		f.Groups[name] = uniqueSorted(members)
	}
	return f
}

func uniqueSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
