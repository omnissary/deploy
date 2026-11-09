{
  description = "NixOS machine deployment CLI";

  inputs = {
    nixpkgs.follows = "omnixiah/nixpkgs";

    omnixiah = {
      url = "tarball+https://git.tatikoma.dev/omnixiah/omnixiah/archive/master.tar.gz";
      inputs.deploy.follows = "";
    };

    flake-parts.follows = "omnixiah/flake-parts";
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
        {
          pkgs,
          system,
          lib,
          ...
        }:
        let
          inherit (lib) assertMsg hasSuffix;
          deploy = pkgs.callPackage ./package.nix { };
          devtools = import ./nix/devtools.nix { inherit pkgs; };
        in
        {
          _module.args.pkgs =
            if hasSuffix "-linux" system then
              inputs.omnixiah.pkgs.${system}
            else
              import inputs.nixpkgs { inherit system; };
          packages.default = deploy;
          checks =
            assert assertMsg (
              inputs.omnixiah.inputs.deploy.outPath == inputs.self.outPath
            ) "omnixiah must use the root deploy checkout";
            import ./tests {
              inherit pkgs deploy;
              disko = inputs.omnixiah.inputs.disko;
            };

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
