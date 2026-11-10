# shellcheck shell=bash

pgp_fingerprint() {
  gpg --batch --with-colons --list-secret-keys "$1" |
    awk -F: '$1 == "fpr" && !seen++ { print $10 }'
}

import_pgp_identity() {
  gpg --batch --import "$1"
  gpg --batch --with-colons --show-keys "$1" |
    awk -F: '$1 == "fpr" && !seen++ { print $10 }'
}

generate_pgp_identity() {
  local identity=$1 fingerprint
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "$identity" ed25519 sign 0
  fingerprint=$(pgp_fingerprint "$identity")
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$fingerprint" cv25519 encr 0
  printf '%s\n' "$fingerprint"
}
