{ pkgs, deploy }:
let
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
        { outputs = _: let
          inherit (builtins) appendContext listToAttrs;
          prebuilt = path: appendContext path (listToAttrs [{ name = path; value.path = true; }]);
        in {
          nixosConfigurations.target.config = {
            nixpkgs.hostPlatform.system = "${pkgs.stdenv.hostPlatform.system}";
            system.build.toplevel = prebuilt "${nodes.target.specialisation.updated.configuration.system.build.toplevel}";
          };
          deploy = { schemaVersion = 1; machines.target = { hostKey = true; initrdSSH = false; }; };
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
  testScript = testLib.prelude + ''
    start_all()
    controller.wait_for_unit("multi-user.target")
    target.wait_for_unit("sshd")

    with subtest("provision credentials through the packaged CLI"):
        controller.succeed("prepare-deploy-test")
        authorize_controller(target)
        run_deploy("machine", "provision", "target")
        run_deploy("host", "set", "target", "target")
        controller.succeed("cd /root/repo && find vars -type f -print0 | sort -z | xargs -0 sha256sum > /root/before-provision")
        run_deploy("machine", "provision", "target")
        controller.succeed("cd /root/repo && sha256sum --check /root/before-provision")

    with subtest("arrange the managed bootstrap host identity"):
        controller.succeed("sops --decrypt --input-type binary --output-type binary /root/repo/vars/secrets/target/openssh/ssh_host_ed25519_key | ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/root/bootstrap-hosts root@target 'umask 077; cat > /etc/ssh/ssh_host_ed25519_key'")
        target.succeed("systemctl restart sshd")
        target.wait_for_unit("sshd")
        # The running daemon retains its key; deployment must repair the missing file.
        target.succeed("rm /etc/ssh/ssh_host_ed25519_key")

    with subtest("copy a real system closure and activate it over SSH"):
        run_deploy("machine", "deploy", "target")
        target.wait_for_unit("sshd")
        assert target.succeed("cat /etc/deploy-test-generation").strip() == "updated"
        remote_public = target.succeed("ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key").split()[:2]
        local_public = controller.succeed("cat /root/repo/vars/secrets/target/openssh/ssh_host_ed25519_key.pub").split()[:2]
        assert remote_public == local_public, "deployed host key differs from provisioned identity"
        controller.fail("test -e /root/repo/vars/secrets/target/initrd-ssh/id_ed25519")

    with subtest("repeat deployment preserves identity and encrypted material"):
        output = run_deploy("machine", "deploy", "target")
        assert "already matches" in output, "repeat deploy did not recognize the managed host key"
        controller.succeed("cd /root/repo && sha256sum --check /root/before-provision")
        assert target.succeed("cat /etc/deploy-test-generation").strip() == "updated"

    with subtest("failed transport cannot activate or generate credentials"):
        target.succeed("systemctl stop sshd")
        expect_deploy_failure("SSH transport failure", "ssh", "machine", "deploy", "target")
        controller.succeed("cd /root/repo && sha256sum --check /root/before-provision")
        assert target.succeed("cat /etc/deploy-test-generation").strip() == "updated"
  '';
}
