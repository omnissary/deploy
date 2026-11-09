{ lib, config, ... }:
let
  inherit (lib) mkOption types;
in {
  options.deploy = mkOption {
    type = types.attrs;
    default = { };
    description = "Versioned public deploy policy; validated against the Go metadata contract.";
  };
  config.flake.deploy = import ../internal/manifest/resolve.nix {
    nixosConfigurations = config.flake.nixosConfigurations or { };
    deploy = config.deploy;
  };
}
