{ system, toplevel }:
let
  prebuilt = import ./prebuilt.nix;
in
{
  nixosConfigurations.target.config = {
    nixpkgs.hostPlatform = { inherit system; };
    system.build.toplevel = prebuilt toplevel;
  };
  deploy = {
    schemaVersion = 2;
    machines.target = {
      inherit system;
      hostKey = true;
      initrdSSH = false;
    };
  };
}
