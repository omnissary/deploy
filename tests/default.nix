{
  pkgs,
  deploy,
  disko,
}:
let
  inherit (pkgs.lib) optionalAttrs;
  inherit (pkgs.lib.meta) availableOn;
  inherit (pkgs.stdenv) hostPlatform;
  zfsInstall =
    hostPlatform.isLinux
    && hostPlatform.isEfi
    && availableOn hostPlatform pkgs.zfs
    && availableOn hostPlatform pkgs.OVMF;
in
{
  fast = {
    runner = import ./runner.nix { inherit pkgs; };
    contract = import ./contract.nix { inherit pkgs; };
    cli = import ./cli { inherit pkgs deploy; };
  };
  e2e =
    optionalAttrs hostPlatform.isLinux {
      ssh-deploy = import ./vm/ssh-deploy.nix { inherit pkgs deploy; };
    }
    // optionalAttrs zfsInstall {
      zfs-install = import ./vm/zfs-install.nix {
        inherit pkgs deploy;
        diskoModule = disko.nixosModules.disko;
      };
    };
}
