package vars

import (
	"path/filepath"
	"regexp"
)

const (
	segSecrets  = "vars/secrets"
	segShared   = "shared"
	segOpenSSH  = "openssh"
	segInitrd   = "initrd-ssh"
	segAdmin    = "vars/admin"
	fileHostKey = "ssh_host_ed25519_key"
	fileInitKey = "id_ed25519"
)

// Regex constants for SOPS creation rules.
const (
	GenericMachineRegex = segSecrets + `/[^/]+\.yaml$`
	GenericSharedRegex  = segSecrets + `/` + segShared + `/[^/]+\.yaml$`
	AdminVarsRegex      = segAdmin + `/.+$`
	GenericInitrdRegex  = segSecrets + `/[^/]+/` + segInitrd + `/` + fileInitKey + `$`
	GenericHostKeyRegex = segSecrets + `/[^/]+/` + segOpenSSH + `/` + fileHostKey + `$`
)

// Regex builders for per-machine/group SOPS creation rules.

func MachineSecretsRegex(machine string) string {
	return segSecrets + "/" + regexp.QuoteMeta(machine) + `\.yaml$`
}

func MachineVarsRegex(machine string) string {
	return segSecrets + "/" + regexp.QuoteMeta(machine) + `/.+$`
}

func SharedSecretsRegex(group string) string {
	return segSecrets + "/" + segShared + "/" + regexp.QuoteMeta(group) + `\.yaml$`
}

// File path builders.

func MachineSecretsPath(flakeDir, machine string) string {
	return filepath.Join(flakeDir, segSecrets, machine+".yaml")
}

func SharedSecretsDir(flakeDir string) string {
	return filepath.Join(flakeDir, segSecrets, segShared)
}

func SharedSecretsPath(flakeDir, group string) string {
	return filepath.Join(SharedSecretsDir(flakeDir), group+".yaml")
}

func MachineHostKeyDir(flakeDir, machine string) string {
	return filepath.Join(flakeDir, segSecrets, machine, segOpenSSH)
}

func MachineHostKeyPath(flakeDir, machine string) string {
	return filepath.Join(MachineHostKeyDir(flakeDir, machine), fileHostKey)
}

func MachineHostKeyPubPath(flakeDir, machine string) string {
	return MachineHostKeyPath(flakeDir, machine) + ".pub"
}

func MachineInitrdKeyDir(flakeDir, machine string) string {
	return filepath.Join(flakeDir, segSecrets, machine, segInitrd)
}

func MachineInitrdKeyPath(flakeDir, machine string) string {
	return filepath.Join(MachineInitrdKeyDir(flakeDir, machine), fileInitKey)
}

func MachineInitrdKeyPubPath(flakeDir, machine string) string {
	return MachineInitrdKeyPath(flakeDir, machine) + ".pub"
}

func AdminDir(flakeDir string) string {
	return filepath.Join(flakeDir, segAdmin)
}

// Glob builders.

func MachineSecretsGlob(flakeDir string) string {
	return filepath.Join(flakeDir, segSecrets, "*.yaml")
}

func SharedSecretsGlob(flakeDir string) string {
	return filepath.Join(flakeDir, segSecrets, segShared, "*.yaml")
}

func MachineHostKeyGlob(flakeDir string) string {
	return filepath.Join(flakeDir, segSecrets, "*", segOpenSSH, fileHostKey)
}

func MachineInitrdKeyGlob(flakeDir string) string {
	return filepath.Join(flakeDir, segSecrets, "*", segInitrd, fileInitKey)
}

func AdminGlob(flakeDir string) string {
	return filepath.Join(flakeDir, segAdmin, "*")
}

// MachineFiles returns the absolute paths of the encrypted files belonging to a
// machine. Used by UpsertMachineRules to re-key after a rule change.
func MachineFiles(flakeDir, machine string) []string {
	return []string{
		MachineSecretsPath(flakeDir, machine),
		MachineHostKeyPath(flakeDir, machine),
		MachineInitrdKeyPath(flakeDir, machine),
	}
}

func SessionKeyPath(flakeDir, name string) string {
	return filepath.Join(AdminDir(flakeDir), name+"-age-key")
}

func SessionKeyPubPath(flakeDir, name string) string {
	return SessionKeyPath(flakeDir, name) + ".pub"
}
