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
```

### secret

Manage per-machine SOPS-encrypted YAML secrets at `machines/<machine>/secrets.yaml`.

```
deploy secret ensure <machine>             # create secrets file if absent
deploy secret get <machine> <key>          # decrypt and print a value
deploy secret set <machine> <key>          # read value from stdin and write
deploy secret update <machine>             # re-encrypt with current .sops.yaml keys
```

### machine

NixOS machine lifecycle.

```
deploy machine init <machine> <host>       # bootstrap via nixos-anywhere
deploy machine build <machine>             # build system toplevel
deploy machine eval <machine> <attr>       # evaluate config attribute (JSON output)
deploy machine audit <machine>             # check closure for source leaks
deploy machine deploy <machine>            # deploy to running machine
deploy machine ssh <machine>               # open interactive SSH session
deploy machine unlock-zfs <machine>        # send ZFS root key to initrd listener
```

`init` flags: `--port` (default `22`), `--phases` (default `kexec,disko,install,reboot`),
`--kexec-flavor` (default `zfs`), `--kexec` (explicit tarball path, skips auto-build).  
`unlock-zfs` flag: `--initrd-port` (default `2222`).

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
