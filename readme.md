# deploy

Deploy manages NixOS installation, deployment, encrypted credentials, and PKI.
It supports ZFS encryption, interactive LUKS unlock, and executable installers
such as NAND flashers.

## Machine policy

Import `deploy.flakeModules.default` into a flake-parts flake and declare its
`deploy` option. Plain flakes can expose the same `deploy` output. Schema version
2 is required. Declare machine capabilities explicitly.

```nix
{
  deploy = {
    schemaVersion = 2;
    machines.server = {
      system = "x86_64-linux";
      rootFS = "zfs";
      hostKey = true;
      initrdSSH = true;
      initrdPort = 6666;
      installer.backend = "nixos-anywhere";
      unlock = "zfs";
      pools.rpool = {
        keyPath = "/run/zfs-keys/rpool.key";
        secret = "rpool-root-key";
        format = "hex";
      };
      requiredSecrets = [
        { name = "server"; key = "yggdrasil"; }
        { name = "server"; key = "tls-cert"; }
        { name = "server"; key = "tls-key"; }
        { name = "clients"; group = true; key = "ca-cert"; }
      ];
    };
    machines.board = {
      system = "armv7l-linux";
      rootFS = "ubifs";
      installer = {
        backend = "executable";
        attribute = "config.system.build.nandFlash";
      };
    };
  };
}
```

`hostKey` and `initrdSSH` declare which SSH identities deploy manages. Both
default to false. A machine that manages its own identities can leave them off.
Nix configuration remains responsible for installing and consuming credentials.

`requiredSecrets` lists encrypted YAML entries needed for deployment. `name`
selects `vars/secrets/<name>.yaml`. With `group = true`, it selects
`vars/secrets/shared/<name>.yaml`. These references require existing entries.
Provisioning does not generate their application credentials.

Pool bindings require an explicit `secret` and absolute target `keyPath`. The
optional `format` names the pool's ZFS `keyformat`: `hex` or `passphrase`.
Provisioning generates a missing key only when `format` is set, and rejects
existing keys that do not match it. Hex keys contain 64 hexadecimal characters.
Without `format`, the key must already exist and is delivered as stored.

## Machine operations

Run commands from your infrastructure flake or select it with `--flake`.

```sh
deploy init --admin-pgp <fingerprint>
deploy machine inspect --json server
deploy machine provision server
deploy machine build server
deploy machine eval server networking.hostName
deploy machine audit server
deploy machine init server 192.0.2.1
deploy machine deploy server
deploy machine ssh server
deploy machine unlock server
```

`build`, `eval`, `audit`, and `init --build-only` operate without credentials.
`provision` creates declared host, initrd, and storage credentials and reconciles
SOPS recipients. Create application identities and certificates with their
explicit lifecycle commands before installation or deployment.

`deploy` checks its declared SSH identities, storage entries, required secrets,
and recipient synchronization. Those checks read encrypted file metadata.
Deployment does not require public Yggdrasil JSON or PKI inventory.

`unlock` requires the declared initrd SSH capability and destination. ZFS unlock
reads only the declared pool keys. LUKS unlock runs the target's interactive
`unlock` command. Application secrets and runtime SSH host keys do not gate
root-volume unlock.

Remote installation uses nixos-anywhere and builds the declared system's
toplevel and Disko script. Options include `--port`, `--phases`, `--kexec-flavor`,
`--kexec`, and repeatable `--ssh-option`. Default phases are
`kexec,disko,install,reboot`. Kexec is built only when selected phases need it.
An executable installer builds and runs its `config.system.build.*` artifact.
It does not elevate privileges. Finish post-flash configuration over the board's
network or USB connection.

```sh
deploy machine init --build-only board
deploy machine deploy --host 192.0.2.9 server
deploy machine unlock --initrd-port 2222 server
deploy kexec --flavor zfs
deploy kexec debug --flavor zfs
```

A deployment host override applies to that invocation. Successful remote
installation records the destination under the `ssh` and `unlock` address tags.
The images flake must provide `kexec-zfs` or `kexec-ext4` for the selected system.

## Secrets, hosts, and groups

```sh
deploy host get server
deploy host set server 200::1
deploy host set --tag unlock server 192.0.2.1
deploy group create clients
deploy group add clients server
deploy key admin list
deploy key admin add <fingerprint>
deploy key session ensure
deploy key session unlock
deploy secret list server
deploy secret get server <key>
deploy secret set server <key> < value.txt
deploy secret del server <key>
deploy secret mv server <key> <destination>
deploy secret verify
deploy sync --dry-run
deploy sync
```

Hosts use a structured YAML registry with `addresses` and `groups`. Addresses
can be plain strings or tagged mappings with `ssh`, `unlock`, and `default`.
Manage group membership and address bindings explicitly.

Deploy generates `.sops.yaml` from admin and session recipients, managed SSH
host public keys, and group membership. `sync` reconciles recipients and resumes
interrupted re-encryption. A dry run needs no decryption key. Secret writes and
moves preserve recipient policy and do not generate credentials.

Session unlock requires `XDG_RUNTIME_DIR`. Session keys can decrypt consumer
material but cannot decrypt admin signing state.

## Yggdrasil identities

```sh
deploy key yggdrasil ensure server
deploy key yggdrasil show --json server
deploy key yggdrasil rotate server
```

These commands explicitly manage the `yggdrasil` entry in the machine's SOPS
YAML file. Ensure preserves an existing Ed25519 PKCS#8 key. Rotation archives
the old key in encrypted admin storage. Identity commands write public metadata
to `vars/public/<machine>/yggdrasil.json` for Nix consumers. They do not change
host addresses or group membership.

## Certificates and authorities

Named policies belong under `deploy.authorities`, `deploy.certificates`, and
`deploy.trust`. PKI commands use these declarations. Pass `--spec policy.json`
to operate with a public specification independently of Nix evaluation.

```nix
{
  deploy.authorities.root = {
    subject = "Infrastructure issuer";
    algorithm = "p256";
    validityDays = 3650;
  };
  deploy.certificates.server-client = {
    issuer = "root";
    subject = "server";
    usage = [ "clientAuth" ];
    validityDays = 90;
    renewBeforeDays = 30;
    target = {
      name = "server";
      chain = "tls-cert";
      key = "tls-key";
    };
  };
  deploy.trust.clients = [ "root" ];
}
```

```sh
deploy pki ca create root
deploy pki ca import --cert-file ca.pem --key-file - issuer < private-key.pem
deploy pki cert ensure server-client
deploy pki cert renew server-client
deploy pki cert rotate server-client
deploy pki cert verify --check-key server-client
deploy pki cert export --chain --out client-chain.pem server-client
deploy pki cert revoke --reason 1 server-client
deploy pki cert remove server-client
deploy pki crl generate --out ca-crl.pem root
deploy pki crl verify root
deploy pki trust export --out trusted-ca.pem clients
deploy pki status
```

All PKI mutations are explicit. Ensure reconciles a managed certificate and
renews it when due. Renew preserves its key. Rotate replaces it. Unmanaged
material in a target requires explicit `pki cert import`. Import preserves the
provided certificate and key without issuing a replacement. Certificate and
private-key imports accept files, with `-` selecting stdin for one input.
`cert remove` drops a certificate from the inventory without revoking it. The
certificate stays valid until it expires.
Listing, show, and mutation output is a table by default. Pass `--json` for
the public inventory as JSON. Import responses contain public inventory only. Imported certificates may
share a serial within an issuer generation. Revoking that serial revokes all of
them. Issued certificates always get unique serials.

A target maps `cert`, `key`, `chain`, and `ca` to YAML keys. Each key holds one
role. `cert` holds the leaf, `chain` holds the leaf followed by its issuers, and
`ca` holds the issuers only.

Signing keys and certificate history live in admin-only encrypted state under
`vars/admin/pki/`. Public inventory lives under `vars/pki/`. Authority signing
keys stay in that state. A public-only imported authority can verify certificates
without a local signer. An authority's explicit `target` publishes selected
material to a machine or group.

Keys default to ECDSA P-256. P-384, Ed25519, and RSA-2048/3072/4096 are also
supported. Children cannot outlive their issuer. Server certificates require DNS
or IP SANs. Policy supports subjects, organization, UID, usages, and custom
extensions. Private export requires `--private-key` and writes files with mode
0600. Configure CRL distribution and enforcement in consumers separately.

### Rotation and recovery

```sh
deploy pki ca rotate root
deploy pki trust export --out overlap.pem root
# Distribute overlapping trust and verify consumers before activation.
deploy pki ca activate --generation 2 root
# Reissue dependents and verify rollout before retirement.
deploy pki ca retire --generation 1 root
deploy pki ca recover root
```

Retirement refuses the active generation and known live dependents. Imported
authorities require `--acknowledge-untracked` because external certificates may
exist. CSR creation and signing support delegated and disconnected issuance.

Mutations hold a local repository lock. SOPS writes reject stale state.
Interrupted PKI publication is journaled and retried by the next mutation.
`ca recover` retries publication without issuing a certificate or replacing a
key. Failed CRL signing leaves revocations recorded for the next attempt.
Deploy does not stage or commit generated files.

## Development and testing

Enter the development shell before formatting or testing. Fast checks exercise
the explicit policy contract, operation prerequisites, and packaged CLI. Linux
VM tests exercise SSH deployment and encrypted ZFS installation on disposable
systems. Register tests in `tests/default.nix` and regenerate CI after changing
E2E registrations.

```sh
nix develop
just fmt
just lint
go test ./...
just test
just test contract
just test-e2e
just test-list
just gen-check
```

## License

MIT
