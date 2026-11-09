set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

fmt: fmt-fieldalign fmt-go

fmt-fieldalign:
  betteralign -fix $(go list -mod=vendor . ./cmd/... ./internal/...)

fmt-go:
  gofumpt -w main.go cmd internal
  goimports -regroup -format-only -local git.tatikoma.dev/ -w main.go cmd internal

lint: lint-sh

lint-sh:
  find nix tests -type f -name '*.sh' -print0 | xargs -0 shellcheck -x -P SCRIPTDIR

test name="all":
  #!/usr/bin/env bash
  set -euo pipefail
  system=$(nix eval --raw --impure --expr builtins.currentSystem)
  case "{{name}}" in
    all) checks=(cli compatibility) ;;
    cli|compatibility|ssh-deploy|zfs-install) checks=("{{name}}") ;;
    *) echo "unknown test '{{name}}'" >&2; exit 1 ;;
  esac
  targets=()
  for check in "${checks[@]}"; do targets+=(".#checks.$system.$check"); done
  nix build --no-link --print-build-logs "${targets[@]}"

test-e2e name="all":
  #!/usr/bin/env bash
  set -euo pipefail
  case "{{name}}" in
    all) just test ssh-deploy; just test zfs-install ;;
    ssh-deploy|zfs-install) just test "{{name}}" ;;
    *) echo "expected all, ssh-deploy, or zfs-install" >&2; exit 1 ;;
  esac
