flake:
 let
  inherit (builtins) foldl' isAttrs hasAttr listToAttrs filter attrValues mapAttrs substring stringLength;
  machine = name: system:
   let c = system.config;
       attr = path: fallback: foldl' (v: key: if isAttrs v && hasAttr key v then v.${key} else fallback) c path;
       managed = attr [ "modules" "initrd-networking" "enable" ] false;
       initrd = attr [ "boot" "initrd" "network" "ssh" "enable" ] false;
       supportsSecrets = attr [ "boot" "loader" "supportsInitrdSecrets" ] true;
       zfs = attr [ "modules" "zfs-crypt" "enable" ] false;
       zfsPools = if zfs then attr [ "modules" "zfs-crypt" "pools" ] {} else {};
       diskoPools = attr [ "disko" "devices" "zpool" ] {};
       diskKeys = listToAttrs (filter (v: v != null) (attrValues (mapAttrs (n: p:
         if (p.rootFsOptions.keyformat or "none") != "none" && substring 0 7 (p.rootFsOptions.keylocation or "") == "file://"
         then { name=n; value={keyPath=substring 7 (stringLength p.rootFsOptions.keylocation - 7) p.rootFsOptions.keylocation; format=p.rootFsOptions.keyformat;}; } else null
       ) diskoPools)));
       pools = diskKeys // mapAttrs (n: p: { inherit (p) keyPath; datasets=p.datasets or []; format="hex"; }) zfsPools;
       nand = attr [ "hardware" "allwinner" "chip" "storage" ] "" == "nand";
   in {
     system = attr [ "nixpkgs" "hostPlatform" "system" ] "";
     hostKey = true;
     initrdSSH = initrd && supportsSecrets && (managed || attr [ "boot" "initrd" "network" "ssh" "hostKeys" ] [] != []);
     initrdPort = attr [ "boot" "initrd" "network" "ssh" "port" ] 2222;
     disko = (c.system.build ? diskoScript);
     inherit pools;
     unlock = if pools != {} then "zfs" else if attr [ "modules" "cryptsetup" "askPassword" ] false then "luks" else "";
     installer = if nand && c.system.build ? nandFlash then {backend="executable";attribute="config.system.build.nandFlash";} else if c.system.build ? diskoScript then {backend="nixos-anywhere";} else {backend="unsupported";};
     source = "nixosConfigurations";
   };
  defaults = mapAttrs machine (flake.nixosConfigurations or {});
  declared = flake.deploy or {};
 in { schemaVersion = 1; } // declared // {
   machines = mapAttrs (name: base:
     let extra = declared.machines.${name} or {};
     in base // extra // { installer = base.installer // (extra.installer or {}); pools = base.pools // (extra.pools or {}); }
   ) defaults;
 }
