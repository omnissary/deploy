{
  description = "NixOS machine deployment CLI";

  inputs = {
    nixpkgs.url = "tarball+https://git.tatikoma.dev/corpix/nixpkgs/archive/v2026-02-21.950114.tar.gz";

    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";

    nixos-anywhere.url = "github:nix-community/nixos-anywhere";
    nixos-anywhere.inputs.nixpkgs.follows = "nixpkgs";
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
        { pkgs, system, ... }:
        let
          unwrapped = pkgs.buildGoModule {
            pname = "deploy-unwrapped";
            version = "0.1.0";
            src = pkgs.lib.fileset.toSource {
              root = ./.;
              fileset = pkgs.lib.fileset.gitTracked ./.;
            };
            vendorHash = null;
            meta.mainProgram = "deploy";
          };
        in
        {
          packages.default = pkgs.symlinkJoin {
            name = "deploy";
            paths = [ unwrapped ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              wrapProgram $out/bin/deploy \
                --prefix PATH : ${
                  pkgs.lib.makeBinPath [
                    pkgs.nix
                    pkgs.openssh
                    pkgs.cpio
                    pkgs.ssh-to-age
                    inputs.nixos-anywhere.packages.${system}.default
                  ]
                }
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
