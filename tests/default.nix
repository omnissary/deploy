{
  pkgs,
  deploy,
  disko,
}:
let
  inherit (pkgs.lib) optionalAttrs;
in
{
  compatibility = import ./compatibility.nix { inherit pkgs; };
  cli = import ./cli { inherit pkgs deploy; };
}
// optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
  ssh-deploy = import ./vm/ssh-deploy.nix { inherit pkgs deploy; };
}
// optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
  zfs-install = import ./vm/zfs-install.nix {
    inherit pkgs deploy;
    diskoModule = disko.nixosModules.disko;
  };
}
