# shellcheck shell=bash
set -euo pipefail
umask 077
export GNUPGHOME
GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"
trap 'gpgconf --kill gpg-agent' EXIT
unset SOPS_AGE_KEY SOPS_AGE_KEY_FILE SOPS_AGE_KEY_CMD SOPS_AGE_SSH_PRIVATE_KEY_FILE
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'Deploy test <deploy@example.invalid>' ed25519 sign 0
fingerprint=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')
gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$fingerprint" cv25519 encr 0
deploy --flake "$TEST_REPO" init --admin-pgp "$fingerprint"

deploy_test() { deploy --flake "$TEST_REPO" "$@"; }

expect_failure() {
  local label=$1
  local expected=$2
  shift 2
  if "$@" >failure.log 2>&1; then
    echo "ASSERT FAIL [$label]: command unexpectedly succeeded" >&2
    return 1
  fi
  if ! grep -F -- "$expected" failure.log; then
    echo "ASSERT FAIL [$label]: expected diagnostic '$expected'" >&2
    cat failure.log >&2
    return 1
  fi
}
