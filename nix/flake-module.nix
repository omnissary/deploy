{ lib, config, ... }:
let
  inherit (lib) mkOption types;
in
{
  options.deploy = mkOption {
    type = types.attrs;
    default = {
      schemaVersion = 2;
      machines = { };
    };
    description = "Explicit machine capabilities and credential resource policies.";
  };
  config.flake.deploy = import ./resolve.nix {
    nixosConfigurations = config.flake.nixosConfigurations or { };
    deploy = config.deploy;
  };
}
