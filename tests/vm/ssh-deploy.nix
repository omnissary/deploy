{ pkgs, deploy }:
let
  inherit (builtins) readFile;
  inherit (pkgs) lib writeText;
  inherit (pkgs.omnixiah) runNixOSTest;
  inherit (lib) mkForce;
  testLib = import ./lib.nix { inherit pkgs deploy; };
in
runNixOSTest {
  name = "deploy-ssh";
  globalTimeout = 15 * 60;
  nodes = {
    controller = { nodes, ... }: {
      imports = [ testLib.controller ];
      virtualisation.additionalPaths = [
        nodes.target.specialisation.updated.configuration.system.build.toplevel
      ];
      environment.etc."deploy-test/flake.nix".source = writeText "ssh-deploy-flake.nix" ''
        { outputs = _: import ./fixtures/ssh-deploy.nix {
          system = "${pkgs.stdenv.hostPlatform.system}";
          toplevel = "${nodes.target.specialisation.updated.configuration.system.build.toplevel}";
        }; }
      '';
    };
    target = {
      imports = [ testLib.target ];
      environment.etc."deploy-test-generation".text = "base";
      specialisation.updated.configuration.environment.etc."deploy-test-generation".text =
        mkForce "updated";
    };
  };
  testScript = testLib.prelude + readFile ./ssh-deploy.py;
}
