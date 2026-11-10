{ pkgs, deploy }:
let
  inherit (builtins) readFile;
  inherit (pkgs) writeShellScriptBin;
  inherit (pkgs.lib) mkForce mkMerge;
  nixSettings = import ../lib/nix-settings.nix;
  prepare = writeShellScriptBin "prepare-deploy-test" ''
    set -euo pipefail
    mkdir -p /root/repo /root/.ssh
    cp /etc/deploy-test/flake.nix /root/repo/flake.nix
    cp -rL /etc/deploy-test/fixtures /root/repo/fixtures
    export TEST_REPO=/root/repo
    export TEST_IDENTITY=${../fixtures/admin.asc}
    source ${../lib}/setup.sh
    if [ -e /etc/deploy-test/access-key ]; then
      install -m 600 /etc/deploy-test/access-key /root/.ssh/id_ed25519
      ssh-keygen -y -f /root/.ssh/id_ed25519 > /root/.ssh/id_ed25519.pub
    else
      ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519
    fi
  '';
in
{
  controller = {
    environment.etc."deploy-test/fixtures".source = ./fixtures;
    # The disposable overlay cannot reclaim space from the shared host store.
    nix.enable = true;
    nix.gc.automatic = false;
    nix.optimise.automatic = false;
    nix.settings = mkMerge [
      nixSettings
      {
        min-free = 0;
        substituters = mkForce [ ];
      }
    ];
    environment.systemPackages = with pkgs; [
      deploy
      bash
      coreutils
      gnupg
      iproute2
      jq
      openssh
      sops
      prepare
    ];
    virtualisation = {
      memorySize = 2048;
      cores = 2;
      writableStore = true;
    };
  };
  target = {
    # The disposable overlay cannot reclaim space from the shared host store.
    nix.enable = true;
    nix.gc.automatic = false;
    nix.optimise.automatic = false;
    services.openssh = {
      enable = true;
      settings.PermitRootLogin = "prohibit-password";
      hostKeys = [
        {
          path = "/etc/ssh/ssh_host_ed25519_key";
          type = "ed25519";
        }
      ];
    };
    nix.settings = mkMerge [
      nixSettings
      {
        min-free = 0;
        substituters = mkForce [ ];
      }
    ];
    virtualisation = {
      memorySize = 1024;
      cores = 2;
      writableStore = true;
    };
  };
  prelude = readFile ./lib.py;
}
