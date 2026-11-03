# deploy

Minimal Go CLI for managing NixOS machines. Handles SSH keys, SOPS secrets, host inventory, and machine lifecycle.

## Usage

```
deploy [global options] <command>
```

Global options:

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--flake`, `-f` | `DEPLOY_FLAKE` | `.` | path to flake root |
| `--images-flake` | `DEPLOY_IMAGES_FLAKE` | `git+https://git.tatikoma.dev/corpix/deploy-images` | flake ref for installer images |
| `--system` | `DEPLOY_SYSTEM` | auto-detected from host arch | target NixOS system tuple (e.g. `x86_64-linux`) |
| `--ssh-user` | `DEPLOY_SSH_USER` | `root` | SSH user for remote ops |
| `--known-hosts` | `DEPLOY_KNOWN_HOSTS` | `known_hosts` | local known_hosts file |
| `--hosts-file` | `DEPLOY_HOSTS_FILE` | `hosts` | machine→address registry |
| `--shared-groups-file` | `DEPLOY_SHARED_GROUPS_FILE` | `vars/shared/groups.yaml` | shared secret group registry |
| `--debug`, `-d` | `DEPLOY_DEBUG` | false | enable debug logging |

## Commands

### host

Machine→address registry (YAML file).

```
deploy host get <machine>          # print registered address
deploy host set <machine> <addr>   # register address
```

### key

Generate and encrypt per-machine SSH key pairs. Private keys are stored as SOPS-encrypted binary files; public keys sit alongside them unencrypted.

```
deploy key host <machine>     # ensure openssh host key
deploy key initrd <machine>   # ensure initrd SSH key
deploy key ensure <machine>   # ensure both
deploy key admin list|add|remove <fingerprint>   # admin PGP recipients (re-encrypts via sync)
deploy key session ensure|unlock|remove [--name]  # dev-session age keys; unlock needs XDG_RUNTIME_DIR
```

### secret

Manage SOPS-encrypted YAML secrets. `<name>` is a group from the hosts file
(`vars/secrets/shared/<group>.yaml`) or a machine (`vars/secrets/<machine>.yaml`).

```
deploy secret list [<name>]                         # list keys (no decryption)
deploy secret get <name> <key>                      # decrypt and print a value
deploy secret set <name> <key>                      # read value from stdin and write
deploy secret del <name> <key>                      # delete a key
deploy secret mv <src> <key> <dst> [<key>] [--force] # move/rename; refuses to overwrite without --force
deploy secret verify [<name>]                       # check decryption and integrity of one or all files
deploy secret repair <name> | --file <path> [--yes] # re-sign a file whose integrity check fails, after confirmation
deploy secret update [<name>]                       # sync recipients; with a name also re-encrypt that file
```

`set` and `mv` never generate keys or change recipients. A machine needs a host
key (`machine provision`) before its secrets file can be created, and a new file
is only created while recipients are in sync.

### sync

`.sops.yaml` is generated from the admin PGP keys and session age keys in its
generic rules, the machine host public keys under `vars/secrets/*/openssh/`, and
the groups in the hosts file.

```
deploy sync [--dry-run]   # rewrite .sops.yaml and re-encrypt files whose recipients differ
```

`--dry-run` only reads file metadata and needs no decryption key. A re-encryption
interrupted part-way is completed by the next `sync`.

### machine

NixOS machine lifecycle.

```
deploy machine init <machine> <host>       # provision, then bootstrap via nixos-anywhere
deploy machine provision <machine|group...> # create missing keys, secrets file and ZFS root keys; sync recipients
deploy machine build <machine...>          # build system toplevel
deploy machine eval <machine> <attr>       # evaluate config attribute (JSON output)
deploy machine audit <machine>             # check closure for source leaks
deploy machine deploy <machine>            # deploy to running machine
deploy machine ssh <machine>               # open interactive SSH session
deploy machine unlock <machine>            # send ZFS root key to initrd listener
```

`init` flags: `--port` (default `22`), `--phases` (default `kexec,disko,install,reboot`),
`--kexec-flavor` (default `zfs`), `--kexec` (explicit tarball path, skips auto-build),
`--ssh-option` (extra SSH option, repeatable, prepended to nixos-anywhere SSH calls).  
`unlock` flag: `--initrd-port` (default `2222`).

Only `init` and `provision` create keys or change recipients. `build`, `eval`,
`audit`, `deploy` and `unlock` check that the machine is provisioned and that
recipients are in sync, without decrypting anything, and fail with the command
to run otherwise. Existing keys are never regenerated: a missing public key is
derived from its encrypted private key, a missing private key is an error.

### kexec

Build and test kexec installer images from the images flake.

```
deploy kexec [--flavor zfs|ext4]          # build image, print tarball path
deploy kexec debug [--flavor zfs|ext4]    # build image and boot in QEMU (C-a x to exit)
```

## Images flake

The `--images-flake` flag points to the flake that provides installer images used during
machine bootstrap. Expected outputs:

| Output | Description |
|--------|-------------|
| `packages.x86_64-linux.kexec-ext4` | kexec installer tarball — ext4 variant |
| `packages.x86_64-linux.kexec-zfs`  | kexec installer tarball — ZFS variant  |

Each output is a store directory containing
`nixos-kexec-installer-<flavor>-x86_64-linux.tar.gz`.

## Development

```
nix develop       # enter dev shell (go, gopls, sops, age, ssh-to-age)
nix build         # build the wrapped binary
nix run . -- --help
```

## License

MIT
