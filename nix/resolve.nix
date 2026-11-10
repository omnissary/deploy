# Resolve one machine lazily so unrelated configurations are never evaluated.
flake:
let
  inherit (builtins)
    attrValues
    filter
    foldl'
    hasAttr
    isAttrs
    listToAttrs
    mapAttrs
    stringLength
    substring
    tryEval
    ;

  getAttr =
    config: path: fallback:
    foldl' (
      value: key: if isAttrs value && hasAttr key value then value.${key} else fallback
    ) config path;

  diskoPoolKey =
    name: pool:
    let
      options = pool.rootFsOptions or { };
      location = options.keylocation or "";
      format = options.keyformat or "none";
    in
    if format != "none" && substring 0 7 location == "file://" then
      {
        inherit name;
        value = {
          keyPath = substring 7 (stringLength location - 7) location;
          inherit format;
        };
      }
    else
      null;

  machineDefaults =
    _: machine:
    let
      config = machine.config;
      attr = getAttr config;
      managedInitrd = attr [ "modules" "initrd-networking" "enable" ] false;
      initrdSSH = attr [ "boot" "initrd" "network" "ssh" "enable" ] false;
      supportsSecrets = attr [ "boot" "loader" "supportsInitrdSecrets" ] true;
      zfsEnabled = attr [ "modules" "zfs-crypt" "enable" ] false;
      zfsPools = if zfsEnabled then attr [ "modules" "zfs-crypt" "pools" ] { } else { };
      diskoPools = attr [ "disko" "devices" "zpool" ] { };
      diskKeys = listToAttrs (filter (key: key != null) (attrValues (mapAttrs diskoPoolKey diskoPools)));
      pools =
        diskKeys
        // mapAttrs (_: pool: {
          inherit (pool) keyPath;
          datasets = pool.datasets or [ ];
          format = "hex";
        }) zfsPools;
      configuredDisko =
        attr [ "disko" "devices" "disk" ] { } != { }
        || attr [ "disko" "devices" "nodev" ] { } != { }
        || diskoPools != { };
      hasDisko = configuredDisko && (config.system.build ? diskoScript);
      nand = attr [ "hardware" "allwinner" "chip" "storage" ] "" == "nand";
      detectedSystem = tryEval (attr [ "nixpkgs" "hostPlatform" "system" ] "");
    in
    {
      rootFS = attr [ "fileSystems" "/" "fsType" ] "";
      system =
        if detectedSystem.success && detectedSystem.value != "" then
          detectedSystem.value
        else
          machine.pkgs.stdenv.hostPlatform.system or "";
      hostKey = true;
      initrdSSH = initrdSSH && supportsSecrets && managedInitrd;
      initrdPort = attr [ "boot" "initrd" "network" "ssh" "port" ] 2222;
      disko = hasDisko;
      inherit pools;
      unlock =
        if pools != { } then
          "zfs"
        else if attr [ "modules" "cryptsetup" "askPassword" ] false then
          "luks"
        else
          "";
      installer =
        if nand && config.system.build ? nandFlash then
          {
            backend = "executable";
            attribute = "config.system.build.nandFlash";
          }
        else if hasDisko then
          { backend = "nixos-anywhere"; }
        else
          { backend = "unsupported"; };
      source = "nixosConfigurations";
    };

  declared = flake.deploy or { };
  defaults = mapAttrs machineDefaults (flake.nixosConfigurations or { });
  applyPolicy =
    name: base:
    let
      policy = declared.machines.${name} or { };
    in
    base
    // policy
    // {
      installer = base.installer // (policy.installer or { });
      pools = base.pools // (policy.pools or { });
    };
in
{
  schemaVersion = 1;
}
// declared
// {
  machines = mapAttrs applyPolicy defaults;
}
