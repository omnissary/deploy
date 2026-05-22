{
  description = "NixOS machine deployment CLI";

  inputs = {
    nixpkgs.url = "tarball+https://git.tatikoma.dev/corpix/nixpkgs/archive/v2026-02-21.950114.tar.gz";

    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";

    nixos-anywhere.url = "tarball+https://git.tatikoma.dev/corpix/nixos-anywhere/archive/corpix.tar.gz";
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
          deploy = pkgs.symlinkJoin {
            name = "deploy";
            paths = [ unwrapped ];
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              mkdir -p $out/share/fish/vendor_completions.d $out/nix-support
              ${unwrapped}/bin/deploy fish-completion \
                > $out/share/fish/vendor_completions.d/deploy.fish
              echo 'export XDG_DATA_DIRS='"$out"'/share''${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}' \
                > $out/nix-support/setup-hook

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
