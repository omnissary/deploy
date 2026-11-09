{
  description = "NixOS machine deployment CLI";

  inputs = {
    nixpkgs.url = "tarball+https://git.tatikoma.dev/omnixiah/nixpkgs/archive/omnixiah.tar.gz";

    flake-parts.url = "tarball+https://git.tatikoma.dev/omnixiah/flake-parts/archive/omnixiah.tar.gz";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      flake.flakeModules.default = ./nix/flake-module.nix;

      flake.overlays.default = final: _prev: {
        deploy = final.callPackage ./package.nix { };
      };

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, ... }:
        let
          deploy = pkgs.callPackage ./package.nix { };
          devtools = import ./nix/devtools.nix { inherit pkgs; };
        in
        {
          packages.default = deploy;

          devShells.default = pkgs.mkShellNoCC {
            packages = with pkgs; [
              go
              gopls
              devtools.gotools
              gofumpt
              betteralign
              just

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
