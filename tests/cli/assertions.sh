# shellcheck shell=bash
set -euo pipefail
# shellcheck source=../lib/setup.sh
source "$TEST_SETUP"

expect_failure 'explicit authority prerequisite' 'no such file' deploy machine provision node
test ! -e "$TEST_REPO/vars/admin/pki/root.yaml"
deploy pki ca create root >root-created.json
deploy machine provision node board

cd "$TEST_REPO" || exit 1
test ! -e vars/secrets/board/initrd-ssh/id_ed25519
test ! -e vars/secrets/node/initrd-ssh/id_ed25519
deploy machine inspect --json board | jq -e '.rootFS == "ubifs" and .initrdSSH == false and .installer.backend == "executable"'
deploy key yggdrasil show --json node | jq -e '.address and .publicKey'
deploy host get node | grep -F "$(jq -r .address vars/public/node/yggdrasil.json)"
deploy group show clients | grep -F node
find vars -type f -print0 | sort -z | xargs -0 sha256sum >before-provision
deploy machine provision node board
sha256sum --check before-provision

deploy pki cert verify --check-key node-client
deploy pki trust export --out root.pem root
deploy pki cert export --out client.pem node-client
openssl verify -purpose sslclient -CAfile root.pem client.pem
deploy pki cert export --private-key --out original-key.pem node-client
test "$(stat -c %a original-key.pem)" = 600
deploy pki cert renew node-client >renewed.json
deploy pki cert export --private-key --out renewed-key.pem node-client
cmp original-key.pem renewed-key.pem
deploy pki cert rotate node-client >rotated.json
deploy pki cert export --private-key --out rotated-key.pem node-client
if cmp -s original-key.pem rotated-key.pem; then echo 'ASSERT FAIL: rotation kept the old key' >&2; exit 1; fi

deploy pki cert revoke --reason 1 node-client
expect_failure 'revoked certificate' revoked deploy pki cert verify node-client
deploy pki crl generate --out crl.pem root
deploy pki crl verify root
openssl crl -in crl.pem -CAfile root.pem -verify -noout
deploy pki ca rotate root >root-rotated.json
deploy pki ca show root | jq -e '.active == 1 and (.generations | length) == 2'
deploy pki trust export --out overlap.pem root
test "$(grep -c 'BEGIN CERTIFICATE' overlap.pem)" = 2
expect_failure 'active generation retirement' 'cannot retire active' deploy pki ca retire --generation 1 root
deploy pki ca activate --generation 2 root >activated.json
expect_failure 'live dependents block retirement' 'unexpired certificates' deploy pki ca retire --generation 1 root
# Explicitly revoke every tracked leaf under generation 1 before retiring it.
deploy pki ca show root >before-retirement.json
while IFS= read -r serial; do
  deploy pki cert revoke --issuer root --serial "$serial" --reason 1
done < <(jq -r '.records[] | select(.generation == 1) | .serial' before-retirement.json | sort -u)
deploy pki cert rotate node-client >new-generation-client.json
deploy pki cert verify --check-key node-client
deploy pki ca retire --generation 1 root >retired.json
deploy pki trust export --out current-root.pem root
test "$(grep -c 'BEGIN CERTIFICATE' current-root.pem)" = 1
deploy pki cert export --out current-client.pem node-client
openssl verify -purpose sslclient -CAfile current-root.pem current-client.pem

# A failed destination must leave a recoverable, durable publication journal.
deploy group create publishers
printf fixture | deploy secret set publishers marker
mv vars/secrets/shared/publishers.yaml publishers.backup
mkdir vars/secrets/shared/publishers.yaml
cat >recovery.json <<'EOF'
{"subject":"Recovery test","target":{"name":"publishers","group":true,"cert":"ca-cert","key":"ca-key"}}
EOF
expect_failure 'interrupted publication' 'publication pending' deploy pki ca create --spec recovery.json recovery
deploy pki ca show recovery >recovery-pending.json
jq -e '.incomplete' recovery-pending.json
rmdir vars/secrets/shared/publishers.yaml
mv publishers.backup vars/secrets/shared/publishers.yaml
deploy pki ca recover recovery >recovered.json
test "$(jq -r '.generations[0].fingerprint' recovery-pending.json)" = "$(jq -r '.generations[0].fingerprint' recovered.json)"
deploy pki ca show recovery | jq -e '.incomplete != true and (.generations | length) == 1'
deploy secret get publishers ca-cert >published-ca.pem
openssl x509 -in published-ca.pem -noout -subject | grep -F 'Recovery test'

# A developer session can decrypt consumer material, but cannot use CA signers.
deploy key session ensure
session_export=$(deploy key session unlock)
eval "$session_export"
admin_keyring=$GNUPGHOME
mkdir -m 700 empty-keyring
export GNUPGHOME="$PWD/empty-keyring"
deploy secret get node tls-key >session-client-key.pem
expect_failure 'session cannot access the CA signer' 'sops decrypt' deploy pki ca recover root
gpgconf --kill gpg-agent
export GNUPGHOME="$admin_keyring"

printf 'invalid identity' | deploy secret set node yggdrasil
sha256sum vars/secrets/node.yaml >before-invalid
expect_failure 'corrupt identity is preserved' 'invalid Yggdrasil' deploy key yggdrasil ensure node
sha256sum --check before-invalid
# Public inventory must never contain private PEM material.
if grep -R 'PRIVATE KEY' vars/pki vars/public; then echo 'ASSERT FAIL: public projection exposed a key' >&2; exit 1; fi
