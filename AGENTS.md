# Deploy agent instructions

## Build and test

```sh
go build ./...                         # compile
go test ./...                          # all tests
go test ./internal/hosts/...           # single package
go test ./cmd/... -run TestMigrate     # single test
nix build                              # wrapped binary (adds nix, openssh, cpio, ssh-to-age, nixos-anywhere to PATH)
nix develop                            # pinned development tools
just lint                              # ShellCheck project shell scripts
just test                              # packaged CLI and metadata compatibility
just test-e2e                          # SSH deployment and encrypted-ZFS installation VMs
```

The repo uses vendored dependencies (`vendor/`). Run `go mod vendor` after changing `go.mod`.

The binary at `./deploy` in the repo root is a pre-built artifact, not tracked in git for freshness -- always rebuild with `go build -o deploy .` when testing CLI changes.

## Repository layout

```
main.go                  entry point. Calls cmd.New().Run()
cmd/                     all CLI command implementations (urfave/cli v2)
internal/
  hosts/                 YAML registry: machine->address and group membership
  sops/                  wrapper around getsops/sops. File.go = File (one decrypt, Get/Set/
                         SetIfAbsent/Delete/Rekey, one Save), sops.go = Create/Verify/Repair,
                         model.go = Model -> rules, MakePlan/Apply/Sync, rules.go = .sops.yaml I/O
  keypair/               Ensure for encrypted-private/plaintext-public key pairs (never regenerates)
  vars/                  pure path/regex builders for the vars/ layout (no I/O)
  nix/                   subprocess wrappers for nix build, nix eval, nixos-rebuild, nixos-anywhere
  state/                 per-flake schema version (vars/.deploy.state) for migrate steps
  atomicfile/            atomic Write (replace) and Create (no-clobber) for all persistent files
  agekey/                age keypair generation
  sshkey/                SSH key operations and ssh-to-age conversion
```

The `git.tatikoma.dev/corpix/atlas` dependency provides `errors` (wrapping) and `log` (zerolog) -- use these everywhere instead of stdlib equivalents.

## CLI structure

`cmd.New()` builds the urfave/cli app. `Config` is populated in the app's `Before` hook from global flags and stored in `cli.App.Metadata["deploy.config"]`. Every action retrieves it via `getConfig(ctx)`.

Top-level subcommands: `init`, `host`, `key`, `secret`, `group`, `migrate`, `sync`, `machine`, `kexec`.

Provisioning (generating keys, creating files, changing recipients) happens only in `machine init`, `machine provision`, `key ...`, `group ...` and `sync`. Data commands (`secret set/mv/...`) and use commands (`machine build/eval/audit/deploy/unlock`) must not generate keys or re-key files. Use commands call `requireMachinesProvisioned`. Generated secrets go through `SetIfAbsent`, never `Set`.

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

All paths are constructed via `internal/vars`. Never hard-code them in `cmd/`.

## SOPS rules in .sops.yaml

`.sops.yaml` is generated. `internal/sops/model.go` turns a `Model` (admin PGP keys and session age keys from the generic machine rule, machine age keys from the host `.pub` files on disk, groups from the hosts file) into the full rule list. Rules are matched by path regex:

- Generic machine rule: `vars/secrets/[^/]+\.yaml$` -- recipients = admin PGP keys + session age key
- Per-machine rule: `vars/secrets/<machine>\.yaml$` -- generic rule recipients + machine's own age key (derived from its SSH host key)
- Per-group rule: `vars/secrets/shared/<group>\.yaml$` -- admin PGP + session key + all member machine age keys
- Vars rule: `vars/secrets/<machine>/.+$` -- covers host/initrd key files
- Admin rule: `vars/admin/.+$` -- admin-only

`MakePlan` compares the desired rules with `.sops.yaml` and with the recipients recorded in every encrypted file's metadata (no decryption), `Apply` writes the rules and re-keys only the files that differ, `Sync` does both. A re-key interrupted part-way is picked up by the next sync. In `cmd/`, change recipients only through `syncRecipients(cfg, edit)`. Never edit rules piecemeal. Rules not matching the owned patterns are preserved before the generic fallbacks.

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

`machineDeployCmd` validates and resolves all machines up front, then fans out goroutines gated by a semaphore channel of size `--parallel` (default 3). Errors are collected and joined. All machines are attempted even if some fail.

## Commits

Commit completed work with one commit per feature. Commit changes to these
instructions separately. Do not add AI attribution or co-author trailers.
Stage explicit paths and leave unrelated changes, including reactor-ca, alone.

## Go formatting and command policies

Run `nix develop` and `just fmt` before committing Go changes. The pipeline uses
betteralign, gofumpt, and patched goimports with `git.tatikoma.dev/` as the local
import prefix. Keep long configuration literals and callbacks on multiple lines.
The formatters do not automatically wrap them. Format only deploy's own sources,
leaving vendor and reactor-ca untouched.
Use the declared Go package name for imports. Add an import alias only to resolve
a real name collision. Do not invent aliases based on the repository name.

Declare repository mutations explicitly with `repositoryMutation` beside their
command actions. Generated operations use `commandOperation` and
`operationCommand`. Attach `optionsBeforeArgs` where trailing options must be
rejected. Do not infer locking or validation policies from command names,
prefixes, or positions in the command tree.

## Nix integration tests

Register Nix checks in `tests/default.nix`. Use omnixiah's package set and
`pkgs.omnixiah.runNixOSTest` for Linux VM tests. The omnixiah deploy input
follows the root flake. Keep deploy's overlay independently evaluable to avoid
recursive package evaluation. Follow omnixiah's nixpkgs and flake-parts pins.

Exercise the packaged CLI and real Nix, SOPS, SSH, and installer transports.
Use disposable identities, virtual networks, and disks. Keep fast checks in
`just test` and VM checks in `just test-e2e`. Never target live infrastructure.
Close stdin for unattended CLI calls in VM tests so SSH cannot consume the
test driver protocol. Disable store GC pressure and scheduled maintenance in
disposable guests, and force empty substituters when testing offline.
Run `just lint` for changes to shell scripts; ShellCheck follows sourced helpers.

## Documentation

Write plain prose with short sentences. Do not use semicolons in explanations.
Describe commands and behavior without implementation history or comparisons to
other repositories. Keep development and testing instructions to a brief
paragraph and a command block.
Use plain ASCII punctuation in prose. Use straight quotes and apostrophes.
Avoid smart quotes, curly apostrophes, em dashes, and en dashes.
Format command invocations in documentation with backticks, such as `nix build`.
Use fenced code blocks for multi-line examples.
