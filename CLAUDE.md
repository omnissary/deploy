# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and test

```sh
go build ./...                         # compile
go test ./...                          # all tests
go test ./internal/hosts/...           # single package
go test ./cmd/... -run TestMigrate     # single test
nix build                              # wrapped binary (adds nix, openssh, cpio, ssh-to-age, nixos-anywhere to PATH)
nix develop                            # dev shell with go, gopls, sops, age, ssh-to-age
```

The repo uses vendored dependencies (`vendor/`). Run `go mod vendor` after changing `go.mod`.

The binary at `./deploy` in the repo root is a pre-built artifact, not tracked in git for freshness -- always rebuild with `go build -o deploy .` when testing CLI changes.

## Repository layout

```
main.go                  entry point; calls cmd.New().Run()
cmd/                     all CLI command implementations (urfave/cli v2)
internal/
  hosts/                 YAML registry: machine->address and group membership
  sops/                  thin wrapper around getsops/sops; sops.go = encrypt/decrypt/set/del,
                         rules.go = .sops.yaml creation-rule management
  vars/                  pure path/regex builders for the vars/ layout (no I/O)
  nix/                   subprocess wrappers for nix build, nix eval, nixos-rebuild, nixos-anywhere
  state/                 per-flake schema version (vars/.deploy.state) for migrate steps
  atomicfile/            atomic Write (replace) and Create (no-clobber) for all persistent files
  agekey/                age keypair generation
  sshkey/                SSH key operations and ssh-to-age conversion
```

The `git.tatikoma.dev/corpix/atlas` dependency provides `errors` (wrapping) and `log` (zerolog) -- use these everywhere instead of stdlib equivalents.

## CLI structure

`cmd.New()` builds the urfave/cli app. `Config` is populated in the app's `Before` hook from global flags and stored in `cli.App.Metadata["deploy.config"]`; every action retrieves it via `getConfig(ctx)`.

Top-level subcommands: `init`, `host`, `key`, `secret`, `group`, `migrate`, `machine`, `kexec`.

Name validation uses `requireSimpleName()` (pattern `^[a-z0-9][a-z0-9_-]*$`). Machine-in-flake validation calls `nix.EvalApply` to list `nixosConfigurations`. Group names and machine names are enforced to be disjoint by `requireGroupName()` in `cmd/group.go`.

## vars/ on-disk layout

```
vars/
  secrets/
    <machine>.yaml                      # per-machine encrypted secrets (SOPS YAML)
    <machine>/openssh/ssh_host_ed25519_key     # encrypted SSH host key (SOPS binary)
    <machine>/openssh/ssh_host_ed25519_key.pub # plaintext public key
    <machine>/initrd-ssh/id_ed25519            # encrypted initrd SSH key (SOPS binary)
    <machine>/initrd-ssh/id_ed25519.pub        # plaintext public key
    shared/<group>.yaml                 # per-group encrypted secrets (SOPS YAML)
  admin/                                # admin-only encrypted files
  .deploy.state                         # JSON schema version for migrate
```

All paths are constructed via `internal/vars`; never hard-code them in `cmd/`.

## SOPS rules in .sops.yaml

`.sops.yaml` is generated. `internal/sops/model.go` turns a `Model` (admin PGP keys and session age keys from the generic machine rule, machine age keys from the host `.pub` files on disk, groups from the hosts file) into the full rule list. Rules are matched by path regex:

- Generic machine rule: `vars/secrets/[^/]+\.yaml$` -- recipients = admin PGP keys + session age key
- Per-machine rule: `vars/secrets/<machine>\.yaml$` -- generic rule recipients + machine's own age key (derived from its SSH host key)
- Per-group rule: `vars/secrets/shared/<group>\.yaml$` -- admin PGP + session key + all member machine age keys
- Vars rule: `vars/secrets/<machine>/.+$` -- covers host/initrd key files
- Admin rule: `vars/admin/.+$` -- admin-only

`MakePlan` compares the desired rules with `.sops.yaml` and with the recipients recorded in every encrypted file's metadata (no decryption), `Apply` writes the rules and re-keys only the files that differ, `Sync` does both. A re-key interrupted part-way is picked up by the next sync. In `cmd/`, change recipients only through `syncRecipients(cfg, edit)`; never edit rules piecemeal. Rules not matching the owned patterns are preserved before the generic fallbacks.

## Hosts file format

`internal/hosts` reads/writes a YAML file at the path given by `--hosts-file`. Two valid address formats per machine:

```yaml
addresses:
  alice: 10.0.0.1                  # plain string -- used as fallback for any operation tag
  bob:
    ssh: 10.0.0.2                  # used by machine ssh / machine deploy
    unlock: 1.2.3.4                # used by machine unlock
    default: 10.0.0.2              # optional explicit fallback for unlisted tags
groups:
  web: [alice, bob]
```

Legacy flat format (`machine: addr` at top level) is still read and rewritten on next save. `GetAddress(path, machine, tag)` returns the tag-specific address or falls back to `Default`.

## Atomic writes

All persistent writes go through `internal/atomicfile`: `Write` replaces a file via a unique temp file, fsync and rename; `Create` does the same but fails with `os.ErrExist` instead of overwriting. Never use `os.WriteFile` for files under the flake.

## multi-machine deploy

`machineDeployCmd` validates and resolves all machines up front, then fans out goroutines gated by a semaphore channel of size `--parallel` (default 3). Errors are collected and joined; all machines are attempted even if some fail.
