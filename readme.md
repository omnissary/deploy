# deploy

Deploy manages NixOS machines, SOPS secrets, SSH identities, and certificate
authorities. It supports native ZFS encryption, legacy LUKS unlock, and
CHIP NAND/UBIFS installation.

## Getting started

Run commands from your infrastructure flake, or select it with `--flake`.
Initialize its admin recipients before provisioning a machine.

```sh
deploy init --admin-pgp <fingerprint>
deploy machine inspect --json <machine>
deploy machine provision <machine>
deploy machine init <machine> <host>
deploy machine deploy <machine>
```

Provisioning creates missing credentials and reconciles recipients. It preserves
existing keys. A missing public key is recovered from its encrypted private key.
A missing private key or an invalid identity causes an error.

Builds and deployments require provisioned credentials and current recipients.
They check this without decrypting credentials or creating replacements.
Run the provisioning command reported by an error before retrying.

Use `deploy --help` and `deploy <command> --help` for options. Options precede
positional arguments.

| Global option | Environment | Default |
| --- | --- | --- |
| `--flake`, `-f` | `DEPLOY_FLAKE` | `.` |
| `--images-flake` | `DEPLOY_IMAGES_FLAKE` | `git+https://git.tatikoma.dev/corpix/deploy-images` |
| `--system` | `DEPLOY_SYSTEM` | Host architecture |
| `--ssh-user` | `DEPLOY_SSH_USER` | `root` |
| `--known-hosts` | `DEPLOY_KNOWN_HOSTS` | `known_hosts` |
| `--hosts-file` | `DEPLOY_HOSTS_FILE` | `hosts` |
| `--debug`, `-d` | `DEPLOY_DEBUG` | `false` |

## Deployment policy

Import `deploy.flakeModules.default` into a flake-parts flake and declare its
`deploy` option. You can also expose the policy directly as a flake output.
Deploy fills omitted machine fields from `nixosConfigurations`. It evaluates
only the selected machine and rejects unsupported schema versions.

```nix
{
  deploy = {
    schemaVersion = 1;
    machines.example = {
      groups = [ "clients" ];
      yggdrasil = true;
      certificates = [ "example-client" ];
    };
    authorities.root = {
      subject = "Infrastructure issuer";
      algorithm = "p256";
      validityDays = 3650;
    };
    certificates.example-client = {
      issuer = "root";
      subject = "example.backbone";
      usage = [ "clientAuth" ];
      validityDays = 90;
      renewBeforeDays = 30;
      target = {
        name = "example";
        cert = "tls-cert";
        chain = "tls-cert";
        key = "tls-key";
      };
    };
    trust.clients = [ "root" ];
  };
}
```

Machine policy can override `system`, `hostKey`, `initrdSSH`, `initrdPort`,
`installer`, `pools`, `groups`, tagged `addresses`, Yggdrasil settings, and
certificate names. Provisioning reconciles declared memberships while preserving
manually maintained groups. Create or import declared authorities explicitly
before provisioning certificates.

## Machines

```sh
deploy machine provision <machine-or-group...>
deploy machine build <machine...>
deploy machine eval <machine> <attribute>
deploy machine audit <machine>
deploy machine deploy <machine...>
deploy machine ssh <machine>
deploy machine unlock <machine>
```

For remote installation, `deploy machine init <machine> <host>` uses
nixos-anywhere. Its options include `--port`, `--phases`, `--kexec-flavor`,
`--kexec`, and repeatable `--ssh-option`. The default phases are
`kexec,disko,install,reboot`. A kexec image is built only when requested phases
need one. Use `deploy kexec` to build an installer or `deploy kexec debug` to
boot it in QEMU. The images flake must provide `kexec-zfs` or `kexec-ext4`
packages for the selected system.

For NAND boards, `deploy machine init --build-only pocketchip` builds the
installer. `deploy machine init pocketchip` runs its declared
`config.system.build.*` executable. It does not elevate privileges. After
flashing, complete configuration over USB or the board's network connection.
Unsupported installers fail before provisioning or building.

ZFS pool policy sets `keyPath`, `format`, an optional `secret`, and optional
`datasets`. The secret defaults to `<pool>-root-key`. Raw keys are stored as
base64, hex keys contain 64 hexadecimal characters, and passphrases remain text.
`deploy machine unlock` delivers the stored key to initrd SSH. Use
`--initrd-port` to override its configured port. Pool keys are never put into
installer images or rotated by provisioning. Legacy LUKS unlock runs the
existing interactive initrd command without creating passphrases or changing
key slots.

## Secrets and identities

```sh
deploy host get <machine>
deploy host set <machine> <address>
deploy key host <machine>
deploy key initrd <machine>
deploy key admin list
deploy key admin add <fingerprint>
deploy key session ensure
deploy key session unlock
deploy secret list <machine-or-group>
deploy secret get <machine-or-group> <key>
deploy secret set <machine-or-group> <key> < value.txt
deploy secret del <machine-or-group> <key>
deploy secret mv <source> <key> <destination>
deploy secret verify
deploy sync --dry-run
deploy sync
```

Machine secrets live under `vars/secrets/`. Group secrets live under
`vars/secrets/shared/`. Private SSH keys are SOPS encrypted and public keys sit
beside them. Deploy generates `.sops.yaml` from admin and session recipients,
machine public keys, and group membership. Use `deploy sync` after recipient
changes. It resumes interrupted re-encryption. A dry run needs no decryption key.

Session unlock requires `XDG_RUNTIME_DIR`. Session keys can decrypt consumer
material but cannot decrypt admin signing keys. Secret writes and moves do not
generate credentials or change recipients.

```sh
deploy key yggdrasil ensure <machine>
deploy key yggdrasil show --json <machine>
deploy key yggdrasil rotate <machine>
```

Yggdrasil identities use Ed25519 PKCS#8 PEM keys. Rotation archives the previous
key in admin storage. Public projections are written to
`vars/public/<machine>/yggdrasil.json` for use by Nix modules. Declared address
bindings are refreshed without editing Nix source.

## Certificates

PKI commands use declared policy by default. Pass `--spec policy.json` to use
the same resource fields without Nix evaluation. Inspection of stored state also
works without Nix. Initialize SOPS admin rules before using PKI commands.

```sh
deploy pki ca create --spec root.json root
deploy pki ca import --cert-file ca.pem --key-file ca-key.pem issuer
deploy pki cert ensure example-client
deploy pki cert renew example-client
deploy pki cert rotate example-client
deploy pki cert verify --check-key example-client
deploy pki cert export --chain --out client-chain.pem example-client
deploy pki cert revoke --reason 1 example-client
deploy pki crl generate --out ca-crl.pem issuer
deploy pki crl verify issuer
deploy pki trust export --out trusted-ca.pem clients
deploy pki status
```

New signing keys use ECDSA P-256 and admin-only SOPS storage. P-384, Ed25519,
and RSA-2048/3072/4096 are also supported. Roots default to ten years,
intermediates to five years, and leaves to 90 days. Children cannot outlive
their issuer. Leaves default to server authentication and require DNS or IP
SANs unless another usage is selected. Policy supports subjects, organization,
UID, key usages, EKUs, and custom extensions.

An authority's `source` can import existing SOPS material. An explicit `target`
publishes it to a machine or group. Otherwise its signing key remains admin-only.
Existing leaf bundles are adopted after validating the key pair and issuer.
Missing or corrupt private keys cause errors rather than replacements.

`deploy pki cert ensure` reconciles policy and renews due certificates.
`deploy pki cert renew` keeps the key. `deploy pki cert rotate` replaces it.
`--force` repeats issuance without bypassing validation or rotating the key.
Private export requires `--private-key` and writes files with mode 0600.
Verification checks chains and recorded revocations. Configure CRL distribution
and enforcement in consumers separately.

### Authority rotation and recovery

```sh
deploy pki ca rotate root
deploy pki trust export --out overlap.pem root
# Distribute overlapping trust and verify consumers before activation.
deploy pki ca activate --generation 2 root
# Reissue dependents and verify rollout before retiring the old generation.
deploy pki ca retire --generation 1 root
deploy pki ca recover root
```

Rotation prepares a generation without activating it. Old keys and history
remain encrypted. Retirement refuses active generations and known live
dependents. Imported authorities require `--acknowledge-untracked` because
external certificates may exist. Trust export does not verify consumer rollout.

For delegated signing, `deploy pki csr create` keeps the request key in admin
storage. Sign with `deploy pki csr sign` and explicit issuer policy. `--ca`
selects an intermediate request. Import the returned certificate under the same
name to recover its matching local key. Deploy validates CSR signatures and SANs
and does not copy requested CA privileges implicitly.

Mutations hold a local repository lock. SOPS writes reject stale state.
Interrupted PKI publication is journaled and retried by the next mutation.
`deploy pki ca recover` retries publication without issuing a certificate or
replacing a key. Failed CRL signing leaves revocations recorded for the next
`deploy pki crl generate` attempt. Encrypted history lives in `vars/admin/pki/`
and public inventory in `vars/pki/`.

Review and stage generated secrets, public projections, and admin state
explicitly. Deploy does not stage or commit files.

## Development and testing

Enter the development shell before formatting or testing. Fast checks exercise
the packaged CLI and compatibility with ZFS, LUKS, and NAND/UBIFS. VM checks
exercise SSH deployment and encrypted ZFS installation on disposable systems.
VM tests require Linux and KVM. The ZFS test also requires ZFS and UEFI firmware
support in the selected package set.

```sh
nix develop
just fmt
just lint
go test ./...
nix build
just test
just test cli
just test compatibility
just test-e2e
just test-e2e ssh-deploy
just test-e2e zfs-install
```

## License

MIT
