# shellcheck shell=bash
set -euo pipefail
command deploy --flake "$TEST_REPO" machine build node >system-path
command deploy --flake "$TEST_REPO" machine eval node fixtureValue | jq -e '. == "node"'
command deploy --flake "$TEST_REPO" machine audit node
command deploy --flake "$TEST_REPO" machine init --build-only board >board-artifact
test ! -e "$TEST_REPO/.sops.yaml"
test ! -e "$TEST_REPO/vars/secrets/node.yaml"
# shellcheck source=../lib/setup.sh
source "$TEST_SETUP"

deploy machine provision node board
test ! -e "$TEST_REPO/vars/admin/pki"
test ! -e "$TEST_REPO/vars/public/node/yggdrasil.json"
test ! -e "$TEST_REPO/vars/secrets/board.yaml"
expect_failure 'explicit runtime requirements' 'missing required secret yggdrasil' deploy machine deploy node
deploy key yggdrasil ensure node
deploy key yggdrasil show --json node | jq -e '.address and .publicKey'
rm "$TEST_REPO/vars/public/node/yggdrasil.json"
printf fixture-cert | deploy secret set node tls-cert 2>default-log
if grep -q '^deploy:' default-log; then
  echo 'ASSERT FAIL: info log appeared without --verbose' >&2
  exit 1
fi
printf fixture-key | command deploy --flake "$TEST_REPO" --verbose secret set node tls-key 2>verbose-log
grep -Fx 'deploy: secret set (key=tls-key target=node)' verbose-log
find "$TEST_REPO/vars" -type f -print0 | sort -z | xargs -0 sha256sum >before-read-only
expect_failure 'deployment does not need public or CA inventory' 'no host registered' deploy machine deploy node
sha256sum --check before-read-only
test ! -e "$TEST_REPO/vars/admin/pki"
deploy secret del node tls-cert
deploy secret del node tls-key
expect_failure 'explicit authority prerequisite' 'no such file' deploy pki cert ensure node-client
deploy pki ca create --json root >root-created.json
deploy pki cert ensure node-client

deploy group create clients
deploy group add clients node
cd "$TEST_REPO" || exit 1
test ! -e vars/secrets/board/initrd-ssh/id_ed25519
test ! -e vars/secrets/node/initrd-ssh/id_ed25519
deploy machine inspect --json board | jq -e '.rootFS == "ubifs" and .initrdSSH == false and .installer.backend == "executable"'
find vars -type f -print0 | sort -z | xargs -0 sha256sum >before-provision
deploy machine provision node board
sha256sum --check before-provision

deploy pki cert verify --check-key node-client
deploy pki cert list | grep -q '^node-client  *root/1 '
deploy pki status | grep -q '^root  *1 '
deploy pki cert list --json | jq -e 'map(.id) == ["node-client"]'
deploy pki trust export --out root.pem root
deploy pki cert export --out client.pem node-client
openssl verify -purpose sslclient -CAfile root.pem client.pem
deploy pki cert export --private-key --out original-key.pem node-client
test "$(stat -c %a original-key.pem)" = 600
deploy pki cert renew --json node-client >renewed.json
deploy pki cert export --private-key --out renewed-key.pem node-client
cmp original-key.pem renewed-key.pem
deploy pki cert rotate --json node-client >rotated.json
deploy pki cert export --private-key --out rotated-key.pem node-client
if cmp -s original-key.pem rotated-key.pem; then echo 'ASSERT FAIL: rotation kept the old key' >&2; exit 1; fi

deploy pki cert revoke --reason 1 node-client
expect_failure 'revoked certificate' revoked deploy pki cert verify node-client
deploy pki crl generate --out crl.pem root
deploy pki crl verify root
openssl crl -in crl.pem -CAfile root.pem -verify -noout
deploy pki ca rotate --json root >root-rotated.json
deploy pki ca show --json root | jq -e '.active == 1 and (.generations | length) == 2'
deploy pki trust export --out overlap.pem root
test "$(grep -c 'BEGIN CERTIFICATE' overlap.pem)" = 2
expect_failure 'active generation retirement' 'cannot retire active' deploy pki ca retire --generation 1 root
deploy pki ca activate --json --generation 2 root >activated.json
expect_failure 'live dependents block retirement' 'unexpired certificates' deploy pki ca retire --generation 1 root
# Explicitly revoke every tracked leaf under generation 1 before retiring it.
deploy pki ca show --json root >before-retirement.json
while IFS= read -r serial; do
  deploy pki cert revoke --issuer root --serial "$serial" --reason 1
done < <(jq -r '.records[] | select(.generation == 1) | .serial' before-retirement.json | sort -u)
deploy pki cert rotate --json node-client >new-generation-client.json
deploy pki cert verify --check-key node-client
deploy pki ca retire --json --generation 1 root >retired.json
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
deploy pki ca show --json recovery >recovery-pending.json
jq -e '.incomplete' recovery-pending.json
rmdir vars/secrets/shared/publishers.yaml
mv publishers.backup vars/secrets/shared/publishers.yaml
deploy pki ca recover --json recovery >recovered.json
test "$(jq -r '.generations[0].fingerprint' recovery-pending.json)" = "$(jq -r '.generations[0].fingerprint' recovered.json)"
deploy pki ca show --json recovery | jq -e '.incomplete != true and (.generations | length) == 1'
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

# Import accepts a private key through stdin and returns only public inventory.
openssl genpkey -algorithm ED25519 -out import-key.pem
openssl req -new -x509 -key import-key.pem -out import-ca.pem -days 30 \
  -subj /CN=Streamed-test-issuer \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
printf '{"subject":"Streamed-test-issuer"}' >import-policy.json
expect_failure 'ambiguous import input' 'only one import input' deploy pki ca import --spec import-policy.json --cert-file - --key-file - ambiguous
cat import-key.pem | deploy pki ca import --json --spec import-policy.json --cert-file import-ca.pem --key-file - streamed >imported-public.json
if grep -F 'PRIVATE KEY' imported-public.json; then echo 'ASSERT FAIL: import exposed private material' >&2; exit 1; fi
