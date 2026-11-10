{
  outputs = _: {
    nixosConfigurations = {
      node.config = {
        nixpkgs.hostPlatform.system = "@system@";
        system.build = { };
      };
      board.config = {
        nixpkgs.hostPlatform.system = "armv7l-linux";
        system.build.nandFlash = "unused";
        hardware.allwinner.chip.storage = "nand";
        fileSystems."/".fsType = "ubifs";
      };
    };
    deploy = {
      schemaVersion = 1;
      machines.node = {
        yggdrasil = true;
        yggdrasilAddressTag = "default";
        groups = [ "clients" ];
        certificates = [ "node-client" ];
        pools.rpool = {
          keyPath = "/run/zfs-keys/rpool.key";
          format = "hex";
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
