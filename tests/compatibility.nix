{ pkgs }:
let
  inherit (pkgs) lib runCommand;
  inherit (lib)
    assertMsg
    evalModules
    mkDefault
    runTests
    types
    ;
  inherit (builtins) toJSON;
  resolve = import ../nix/resolve.nix;
  platform = {
    nixpkgs.hostPlatform.system = mkDefault "x86_64-linux";
    system.build = { };
  };
  networking = {
    modules.initrd-networking.enable = true;
    boot.initrd.network.ssh.enable = true;
    boot.loader.supportsInitrdSecrets = true;
  };
  mkMachine = modules: {
    config =
      (evalModules {
        modules = [
          { _module.freeformType = types.attrsOf types.anything; }
          platform
        ]
        ++ modules;
      }).config;
  };
  metadata =
    (resolve {
      nixosConfigurations = {
        zfs = mkMachine [
          networking
          {
            fileSystems."/".fsType = "zfs";
            modules.zfs-crypt = {
              enable = true;
              pools.rpool.keyPath = "/run/zfs-keys/rpool.key";
            };
          }
        ];
        luks = mkMachine [
          networking
          {
            fileSystems."/".fsType = "btrfs";
            modules.cryptsetup.askPassword = true;
          }
        ];
        board = mkMachine [
          {
            nixpkgs.hostPlatform.system = "armv7l-linux";
            hardware.allwinner.chip.storage = "nand";
            fileSystems."/".fsType = "ubifs";
            system.build = {
              nandFlash = "fixture";
              diskoScript = "unconfigured";
            };
          }
        ];
        disko = mkMachine [
          {
            system.build.diskoScript = "fixture";
            disko.devices.zpool.rpool.rootFsOptions = {
              keyformat = "raw";
              keylocation = "file:///run/keys/rpool";
            };
          }
        ];
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
