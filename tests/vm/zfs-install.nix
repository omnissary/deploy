{
  pkgs,
  deploy,
  diskoModule,
}:
let
  inherit (builtins) readFile;
  inherit (pkgs)
    lib
    runCommand
    openssh
    writeText
    ;
  inherit (lib) mkForce;
  inherit (pkgs.omnixiah) runNixOSTest;
  testLib = import ./lib.nix { inherit pkgs deploy; };
  accessKey = runCommand "deploy-vm-access-key" { nativeBuildInputs = [ openssh ]; } ''
    mkdir $out
    ssh-keygen -q -t ed25519 -N "" -f $out/id_ed25519
  '';
  publicKey = readFile "${accessKey}/id_ed25519.pub";
  keyPath = "/run/zfs-keys/rpool.key";
  initrdKeyPath = "/etc/deploy-test/ssh_host_ed25519_key";
in
runNixOSTest {
  name = "deploy-zfs-install";
  globalTimeout = 25 * 60;
  nodes = {
    controller = { nodes, ... }: {
      imports = [ testLib.controller ];
      virtualisation.additionalPaths = [
        nodes.target.system.build.toplevel
        nodes.target.system.build.diskoScript
      ];
      environment.etc."deploy-test/access-key" = {
        source = "${accessKey}/id_ed25519";
        mode = "0600";
      };
      environment.etc."deploy-test/flake.nix".source = writeText "zfs-install-flake.nix" ''
        { outputs = _: let
          inherit (builtins) appendContext listToAttrs;
          prebuilt = path: appendContext path (listToAttrs [{ name = path; value.path = true; }]);
        in {
          nixosConfigurations.target.config = {
            nixpkgs.hostPlatform.system = "${pkgs.stdenv.hostPlatform.system}";
            boot.initrd.network.ssh.hostKeys = [ "${initrdKeyPath}" ];
            system.build = {
              toplevel = prebuilt "${nodes.target.system.build.toplevel}";
              diskoScript = prebuilt "${nodes.target.system.build.diskoScript}";
            };
          };
          deploy = { schemaVersion = 1; machines.target = {
            rootFS = "zfs"; disko = true; initrdSSH = true; initrdPort = 2222; unlock = "zfs";
            installer.backend = "nixos-anywhere";
            pools.rpool = { keyPath = "${keyPath}"; format = "hex"; };
          }; };
        }; }
      '';
    };
    installer = {
      imports = [ testLib.target ];
      boot.supportedFilesystems = [ "zfs" ];
      networking.hostId = "12ab34cd";
      environment.systemPackages = [
        pkgs.nixos-install-tools
        pkgs.zfs
      ];
      users.users.root.openssh.authorizedKeys.keys = [ publicKey ];
      virtualisation = {
        diskImage = "../deploy-target.qcow2";
        diskSize = 6 * 1024;
        emptyDiskImages = [ 1024 ];
        rootDevice = "/dev/vdb";
        fileSystems."/".autoFormat = true;
      };
    };
    target = {
      imports = [
        testLib.target
        diskoModule
      ];
      networking.hostId = "12ab34cd";
      users.users.root.openssh.authorizedKeys.keys = [ publicKey ];
      environment.etc."deploy-test-installed".text = "encrypted ZFS root";
      system.switch.enable = true;
      boot = {
        loader = {
          systemd-boot.enable = true;
          timeout = 0;
          efi.canTouchEfiVariables = false;
        };
        zfs.devNodes = "/dev/disk/by-partuuid";
        initrd = {
          availableKernelModules = [
            "virtio_pci"
            "virtio_blk"
            "virtio_net"
          ];
          network = {
            ssh = {
              enable = true;
              port = 2222;
              hostKeys = [ initrdKeyPath ];
              authorizedKeys = [ publicKey ];
            };
          };
          systemd.network = {
            enable = true;
            networks."10-test-lan" = {
              matchConfig.Name = "eth1";
              address = [
                "192.168.1.3/24"
                "2001:db8:1::3/64"
              ];
            };
          };
          systemd.services.zfs-import-rpool = {
            path = [ pkgs.coreutils ];
            serviceConfig.StandardOutput = "journal+console";
            preStart = ''
              echo 'deploy test: waiting for encrypted root key'
              while [ ! -s ${keyPath} ]; do sleep 0.2; done
            '';
          };
        };
      };
      disko.devices = {
        disk.root = {
          type = "disk";
          device = "/dev/vda";
          content = {
            type = "gpt";
            partitions = {
              ESP = {
                size = "512M";
                type = "EF00";
                content = {
                  type = "filesystem";
                  format = "vfat";
                  mountpoint = "/boot";
                };
              };
              zfs = {
                size = "100%";
                content = {
                  type = "zfs";
                  pool = "rpool";
                };
              };
            };
          };
        };
        zpool.rpool = {
          type = "zpool";
          options.ashift = "12";
          rootFsOptions = {
            encryption = "aes-256-gcm";
            keyformat = "hex";
            keylocation = "file://${keyPath}";
            mountpoint = "none";
          };
          datasets.root = {
            type = "zfs_fs";
            mountpoint = "/";
            options.mountpoint = "legacy";
          };
        };
      };
      virtualisation = {
        diskImage = "../deploy-target.qcow2";
        diskSize = 6 * 1024;
        useBootLoader = true;
        useEFIBoot = true;
        efi.keepVariables = false;
        efi.OVMF = pkgs.OVMF;
        useDefaultFilesystems = false;
        fileSystems = mkForce { };
        writableStore = mkForce false;
      };
    };
  };
  testScript = testLib.prelude + ''
    def wait_for_initrd_ssh():
        controller.wait_until_succeeds(
            "ssh-keyscan -T 2 -p 2222 -t ed25519 target > /root/initrd-host-key 2>/dev/null",
            timeout=180,
        )
        controller.fail("timeout 2 bash -c 'exec 3<>/dev/tcp/target/22'")
        expected_key = controller.succeed(
            "cat /root/repo/vars/secrets/target/initrd-ssh/id_ed25519.pub"
        ).split()[:2]
        keyscan_output = controller.succeed("cat /root/initrd-host-key")
        offered_keys = [
            line.split()[1:3]
            for line in keyscan_output.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert offered_keys and all(key == expected_key for key in offered_keys), (
            f"initrd SSH identity: expected {expected_key!r}, got {offered_keys!r}"
        )

    controller.start()
    installer.start()
    controller.wait_for_unit("multi-user.target")
    installer.wait_for_unit("sshd")

    with subtest("provision an encrypted root without rotating its key"):
        controller.succeed("prepare-deploy-test")
        run_deploy("machine", "provision", "target")
        controller.succeed("deploy --flake /root/repo secret get target rpool-root-key | sha256sum > /root/pool-key-before")
        run_deploy("machine", "provision", "target")
        controller.succeed("deploy --flake /root/repo secret get target rpool-root-key | sha256sum --check /root/pool-key-before")

    with subtest("install through real nixos-anywhere and Disko"):
        controller.succeed(deploy_command("machine", "init", "--phases", "disko,install", "target", "installer"), timeout=900)
        installer.succeed("test -s /mnt/etc/ssh/ssh_host_ed25519_key && test -s /mnt${initrdKeyPath}")
        installer.fail("test -e /mnt${keyPath}")
        assert installer.succeed("zfs get -H -o value encryption rpool").strip() == "aes-256-gcm"
        installer.succeed("umount -R /mnt && zpool export rpool")
        installer.shutdown()
        run_deploy("host", "set", "target", "target")
        run_deploy("host", "set", "--tag", "unlock", "target", "target")

    with subtest("boot blocks in initrd until deploy delivers the stored key"):
        target.start()
        target.wait_for_console_text("deploy test: waiting for encrypted root key", timeout=180)
        wait_for_initrd_ssh()
        run_deploy("machine", "unlock", "target")
        target.wait_for_unit("multi-user.target", timeout=180)
        assert target.succeed("findmnt -n -o FSTYPE /").strip() == "zfs"
        assert target.succeed("cat /etc/deploy-test-installed").strip() == "encrypted ZFS root"
        assert target.succeed("zfs get -H -o value keystatus rpool").strip() == "available"
        controller.succeed("deploy --flake /root/repo secret get target rpool-root-key | sha256sum --check /root/pool-key-before")

    with subtest("a second cold boot still requires the same stored key"):
        target.shutdown()
        target.start()
        wait_for_initrd_ssh()
        run_deploy("machine", "unlock", "target")
        target.wait_for_unit("multi-user.target", timeout=180)
        assert target.succeed("findmnt -n -o FSTYPE /").strip() == "zfs"
        controller.succeed("deploy --flake /root/repo secret get target rpool-root-key | sha256sum --check /root/pool-key-before")
  '';
}
