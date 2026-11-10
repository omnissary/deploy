# shellcheck shell=bash
set -euo pipefail
umask 077
export GNUPGHOME
GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"
trap 'gpgconf --kill gpg-agent' EXIT
unset SOPS_AGE_KEY SOPS_AGE_KEY_FILE SOPS_AGE_KEY_CMD SOPS_AGE_SSH_PRIVATE_KEY_FILE
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
# shellcheck source=keys.sh
source "$(dirname "${BASH_SOURCE[0]}")/keys.sh"
fingerprint=$(import_pgp_identity "$TEST_IDENTITY")
deploy() { command deploy --flake "$TEST_REPO" "$@"; }
deploy init --admin-pgp "$fingerprint"

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
