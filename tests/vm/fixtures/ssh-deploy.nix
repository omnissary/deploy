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
    schemaVersion = 1;
    machines.target = {
      hostKey = true;
      initrdSSH = false;
    };
  };
}
