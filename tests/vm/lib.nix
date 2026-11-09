{ pkgs, deploy }:
let
  inherit (pkgs)
    bash
    coreutils
    gnupg
    iproute2
    jq
    openssh
    sops
    writeShellScriptBin
    ;
  inherit (pkgs.lib) mkForce;
  prepare = writeShellScriptBin "prepare-deploy-test" ''
    set -euo pipefail
    mkdir -p /root/repo /root/.ssh
    cp /etc/deploy-test/flake.nix /root/repo/flake.nix
    export TEST_REPO=/root/repo
    source ${../lib/setup.sh}
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
    # The disposable overlay cannot reclaim space from the shared host store.
    nix.enable = true;
    nix.gc.automatic = false;
    nix.optimise.automatic = false;
    nix.settings = {
      min-free = 0;
      substituters = mkForce [ ];
      flake-registry = "";
    };
    environment.systemPackages = [
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
    nix.settings = {
      min-free = 0;
      substituters = mkForce [ ];
    };
    virtualisation = {
      memorySize = 1024;
      cores = 2;
      writableStore = true;
    };
  };
  prelude = ''
    import shlex

    def deploy_command(*args):
        return "deploy --flake /root/repo " + shlex.join(args) + " < /dev/null 2>&1"

    def run_deploy(*args):
        return controller.succeed(deploy_command(*args), timeout=240)

    def expect_deploy_failure(label, diagnostic, *args):
        status, output = controller.execute(deploy_command(*args), timeout=90)
        assert status != 0, f"{label}: command unexpectedly succeeded"
        assert diagnostic in output, f"{label}: missing {diagnostic!r} in {output}"

    def authorize_controller(machine):
        public_key = controller.succeed("cat /root/.ssh/id_ed25519.pub").strip()
        machine.succeed("mkdir -p -m 700 /root/.ssh && printf '%s\\n' " + shlex.quote(public_key) + " >> /root/.ssh/authorized_keys")
  '';
}
