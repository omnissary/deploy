{
  outputs = _: {
    nixosConfigurations = {
      node.config = {
        nixpkgs.hostPlatform.system = "@system@";
        fixtureValue = "node";
        system.build.toplevel = builtins.toFile "deploy-test-system" "fixture";
      };
      board.config = {
        nixpkgs.hostPlatform.system = "armv7l-linux";
        system.build.nandFlash = builtins.toFile "nand-test-artifact" "fixture";
        fileSystems."/".fsType = "ubifs";
      };
    };
    deploy = {
      schemaVersion = 2;
      machines = {
        node = {
          system = "@system@";
          hostKey = true;
          requiredSecrets = [
            {
              name = "node";
              key = "yggdrasil";
            }
            {
              name = "node";
              key = "tls-cert";
            }
            {
              name = "node";
              key = "tls-key";
            }
          ];
          pools.rpool = {
            keyPath = "/run/zfs-keys/rpool.key";
            secret = "rpool-root-key";
            format = "hex";
          };
        };
        board = {
          system = "armv7l-linux";
          rootFS = "ubifs";
          installer = {
            backend = "executable";
            attribute = "config.system.build.nandFlash";
          };
        };
      };
      authorities.root.subject = "Deploy test root";
      certificates.node-client = {
        issuer = "root";
        subject = "node";
        usage = [ "clientAuth" ];
        target = {
          name = "node";
          cert = "tls-cert";
          key = "tls-key";
          ca = "tls-ca";
        };
      };
    };
  };
}
