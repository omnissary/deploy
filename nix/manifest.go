// Package nix embeds the Nix expressions shared by the CLI and flake module.
package nix

import _ "embed"

//go:embed resolve.nix
var ManifestExpression string
