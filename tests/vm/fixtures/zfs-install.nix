{
  system,
  toplevel,
  diskoScript,
  keyPath,
  initrdKeyPath,
}:
let
  prebuilt = import ./prebuilt.nix;
in
{
  nixosConfigurations.target.config = {
    nixpkgs.hostPlatform = { inherit system; };
    boot.initrd.network.ssh.hostKeys = [ initrdKeyPath ];
    system.build = {
      toplevel = prebuilt toplevel;
      diskoScript = prebuilt diskoScript;
    };
  };
  deploy = {
    schemaVersion = 1;
    machines.target = {
      rootFS = "zfs";
      disko = true;
      initrdSSH = true;
      initrdPort = 2222;
      unlock = "zfs";
      installer.backend = "nixos-anywhere";
      pools.rpool = {
        inherit keyPath;
        format = "hex";
      };
    };
  };
}
