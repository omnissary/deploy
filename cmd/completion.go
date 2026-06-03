package cmd

import (
	"sort"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
)

// completionMachineNames returns the machine names registered in the hosts file.
// Errors are silently ignored -- completion must never fail.
func completionMachineNames(cfg *Config) []string {
	f, err := hosts.Load(cfg.HostsFile)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(f.Addresses))
	for name := range f.Addresses {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// completionGroupNames returns the group names registered in the hosts file.
// Errors are silently ignored.
func completionGroupNames(cfg *Config) []string {
	f, err := hosts.Load(cfg.HostsFile)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(f.Groups))
	for name := range f.Groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// completionMachineOrGroupNames returns the sorted union of machine and group names
// from the hosts file. Errors are silently ignored.
func completionMachineOrGroupNames(cfg *Config) []string {
	f, err := hosts.Load(cfg.HostsFile)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(f.Addresses)+len(f.Groups))
	for name := range f.Addresses {
		seen[name] = struct{}{}
	}
	for name := range f.Groups {
		seen[name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
