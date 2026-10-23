{
  description = "NixOS machine deployment CLI";

  inputs = {
    nixpkgs.url = "tarball+https://git.tatikoma.dev/omnixiah/nixpkgs/archive/omnixiah.tar.gz";

    flake-parts.url = "tarball+https://git.tatikoma.dev/omnixiah/flake-parts/archive/omnixiah.tar.gz";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";

    nixos-anywhere.url = "tarball+https://git.tatikoma.dev/corpix/nixos-anywhere/archive/corpix.tar.gz";
    nixos-anywhere.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      flake.overlays.default = final: _prev: {
        deploy = final.callPackage ./package.nix {
          nixos-anywhere = inputs.nixos-anywhere.packages.${final.stdenv.hostPlatform.system}.default;
        };
      };

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, system, ... }:
        let
          deploy = pkgs.callPackage ./package.nix {
            nixos-anywhere = inputs.nixos-anywhere.packages.${system}.default;
          };
        in
        {
          packages.default = deploy;

          devShells.default = pkgs.mkShellNoCC {
            packages = with pkgs; [
              go
              gopls
              gotools
              gofumpt

              sops
              age
              ssh-to-age
            ];
            shellHook = ''
              export XDG_DATA_DIRS="${deploy}/share''${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}"
            '';
          };
        };
    };
}
