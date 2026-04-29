{
  description = "NixOS machine deployment CLI";

  inputs = {
    nixpkgs.url = "tarball+https://git.tatikoma.dev/corpix/nixpkgs/archive/v2026-02-21.950114.tar.gz";

    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, ... }:
        {
          packages.default = pkgs.buildGoModule {
            pname = "deploy";
            version = "0.1.0";
            src = ./.;

            # All external dependencies are vendored; no network fetch needed.
            vendorHash = null;

            # The go.mod contains a local replace directive for atlas that is only
            # valid inside the cheburnet-infra monorepo. All atlas packages are
            # already vendored so the directive is safe to drop at build time.
            postPatch = ''
              sed -i '/^replace /d' go.mod
            '';

            meta = with pkgs.lib; {
              description = "NixOS machine deployment CLI";
              mainProgram = "deploy";
              license = licenses.mit;
            };
          };

          devShells.default = pkgs.mkShellNoCC {
            packages = with pkgs; [
              go
              gopls
              gotools

              sops
              age
              ssh-to-age
            ];
          };
        };
    };
}
