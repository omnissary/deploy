{
  pkgs,
  deploy,
  diskoModule,
}:
let
  inherit (builtins) readFile toJSON;
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
        { outputs = _: import ./fixtures/zfs-install.nix {
          keyPath = "${keyPath}";
          initrdKeyPath = "${initrdKeyPath}";
          system = "${pkgs.stdenv.hostPlatform.system}";
          toplevel = "${nodes.target.system.build.toplevel}";
          diskoScript = "${nodes.target.system.build.diskoScript}";
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
  testScript =
    testLib.prelude
    + readFile ./zfs-install.py
    + ''
      run_zfs_install(${
        toJSON [
          "--key-path"
          keyPath
          "--initrd-key-path"
          initrdKeyPath
        ]
      })
    '';
}
