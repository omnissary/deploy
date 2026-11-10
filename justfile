set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

fmt: fmt-fieldalign fmt-go fmt-meta

fmt-fieldalign:
  betteralign -fix $(go list -mod=vendor . ./cmd/... ./internal/... ./nix/...)

fmt-go:
  gofumpt -w main.go cmd internal nix
  goimports -regroup -format-only -local git.tatikoma.dev/ -w main.go cmd internal nix

fmt-meta:
  git ls-files -z '*.nix' | xargs -0 -r nixfmt
  black tests

lint: lint-sh

lint-sh:
  find nix tests -type f -name '*.sh' -print0 | xargs -0 shellcheck -x -P SCRIPTDIR

test name="all":
  python3 tests/run.py --suite fast {{quote(name)}}

test-e2e name="all":
  python3 tests/run.py --suite e2e {{quote(name)}}

test-list suite="all":
  python3 tests/run.py --suite {{quote(suite)}} --list

workflow:
  #!/usr/bin/env bash
  set -euo pipefail
  export E2E_TESTS
  E2E_TESTS=$(python3 tests/run.py --suite e2e --system x86_64-linux --list)
  yq -i '.jobs."test-e2e".strategy.matrix.test = env(E2E_TESTS)' .gitea/workflows/e2e.yaml

gen: workflow

gen-check: gen
  git diff --exit-code -- .gitea/workflows/e2e.yaml
