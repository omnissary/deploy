{ pkgs }:
let
  inherit (builtins) tryEval;
  inherit (pkgs.lib)
    assertMsg
    evalModules
    mkOption
    types
    ;
  declared = {
    schemaVersion = 2;
    machines = {
      zfs = {
        system = "x86_64-linux";
        hostKey = true;
        initrdSSH = true;
        unlock = "zfs";
        pools.rpool = {
          keyPath = "/run/key";
          secret = "root-key";
          format = "hex";
        };
      };
      luks = {
        system = "aarch64-linux";
        initrdSSH = true;
        unlock = "luks";
      };
      board = {
        system = "armv7l-linux";
        rootFS = "ubifs";
        installer = {
          backend = "executable";
          attribute = "config.system.build.nandFlash";
        };
      };
    };
  };
  resolve = import ../nix/resolve.nix;
  resolved = resolve {
    deploy = declared;
    nixosConfigurations.broken = throw "configuration must not be inspected";
  };
  projected =
    (evalModules {
      modules = [
        ../nix/flake-module.nix
        {
          options.flake = mkOption {
            type = types.lazyAttrsOf types.raw;
            default = { };
          };
          config.deploy = declared;
        }
      ];
    }).config.flake.deploy;
in
assert assertMsg (
  resolved == declared && projected == declared
) "Deploy must preserve explicit policy";
assert assertMsg (
  !(tryEval (resolve {
    nixosConfigurations = { };
  })).success
) "Deploy policy is required";
pkgs.runCommand "deploy-policy-contract" { } "touch $out"
