{ pkgs }:
let
  inherit (pkgs) lib runCommand;
  inherit (lib) assertMsg runTests;
  inherit (builtins) toJSON;
  resolve = import ../internal/manifest/resolve.nix;
  platform = {
    nixpkgs.hostPlatform.system = "x86_64-linux";
    system.build = { };
  };
  networking = {
    modules.initrd-networking.enable = true;
    boot.initrd.network.ssh.enable = true;
    boot.loader.supportsInitrdSecrets = true;
  };
  metadata =
    (resolve {
      nixosConfigurations = {
        zfs.config =
          platform
          // networking
          // {
            fileSystems."/".fsType = "zfs";
            modules = {
              initrd-networking.enable = true;
              zfs-crypt = {
                enable = true;
                pools.rpool.keyPath = "/run/zfs-keys/rpool.key";
              };
            };
          };
        luks.config =
          platform
          // networking
          // {
            fileSystems."/".fsType = "btrfs";
            modules = {
              initrd-networking.enable = true;
              cryptsetup.askPassword = true;
            };
          };
        board.config = platform // {
          nixpkgs.hostPlatform.system = "armv7l-linux";
          hardware.allwinner.chip.storage = "nand";
          fileSystems."/".fsType = "ubifs";
          system.build = {
            nandFlash = "fixture";
            diskoScript = "unconfigured";
          };
        };
        disko.config = platform // {
          system.build.diskoScript = "fixture";
          disko.devices.zpool.rpool.rootFsOptions = {
            keyformat = "raw";
            keylocation = "file:///run/keys/rpool";
          };
        };
      };
    }).machines;
  failures = runTests {
    testZfsUnlock = {
      expr = metadata.zfs.unlock;
      expected = "zfs";
    };
    testBootstrapBeforeKeyFiles = {
      expr = metadata.zfs.initrdSSH;
      expected = true;
    };
    testLuksUnlock = {
      expr = metadata.luks.unlock;
      expected = "luks";
    };
    testLuksHasNoGeneratedPoolKeys = {
      expr = metadata.luks.pools;
      expected = { };
    };
    testNandInstaller = {
      expr = metadata.board.installer;
      expected = {
        backend = "executable";
        attribute = "config.system.build.nandFlash";
      };
    };
    testUbifsPreserved = {
      expr = metadata.board.rootFS;
      expected = "ubifs";
    };
    testBoardRequiresNoInitrdIdentity = {
      expr = metadata.board.initrdSSH;
      expected = false;
    };
    testUnconfiguredDiskoIgnored = {
      expr = metadata.board.disko;
      expected = false;
    };
    testDiskoInstaller = {
      expr = metadata.disko.installer.backend;
      expected = "nixos-anywhere";
    };
    testRawPoolKey = {
      expr = metadata.disko.pools.rpool;
      expected = {
        keyPath = "/run/keys/rpool";
        format = "raw";
      };
    };
  };
in
assert assertMsg (failures == [ ]) (toJSON failures);
runCommand "deploy-compatibility" { } "touch $out"
