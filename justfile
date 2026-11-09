set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

fmt: fmt-fieldalign fmt-go

fmt-fieldalign:
  betteralign -fix $(go list -mod=vendor . ./cmd/... ./internal/...)

fmt-go:
  gofumpt -w main.go cmd internal
  goimports -regroup -format-only -local git.tatikoma.dev/ -w main.go cmd internal
