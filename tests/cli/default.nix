{ pkgs, deploy }:
let
  inherit (pkgs) runCommand;
  inherit (pkgs.lib) concatStringsSep isList mapAttrsToList;
  nixSettings = import ../lib/nix-settings.nix;
  nixConfig = concatStringsSep "\n" (
    mapAttrsToList (
      name: value: "${name} = ${if isList value then concatStringsSep " " value else value}"
    ) nixSettings
  );

in
runCommand "deploy-cli-e2e"
  {
    inherit nixConfig;
    passAsFile = [ "nixConfig" ];
    nativeBuildInputs = with pkgs; [
      deploy
      bash
      coreutils
      diffutils
      findutils
      gawk
      gnugrep
      gnupg
      jq
      nix
      openssl
    ];
  }
  ''
    export HOME="$TMPDIR/home"
    export XDG_RUNTIME_DIR="$TMPDIR/runtime"
    mkdir -m 700 "$XDG_RUNTIME_DIR"
    export XDG_CONFIG_HOME="$HOME/.config"
    export NIX_REMOTE="local?root=$TMPDIR/nix"
    mkdir -p "$XDG_CONFIG_HOME/nix" repo
    cp "$nixConfigPath" "$XDG_CONFIG_HOME/nix/nix.conf"
    cp ${./flake.nix} repo/flake.nix
    substituteInPlace repo/flake.nix --replace-fail '@system@' '${pkgs.stdenv.hostPlatform.system}'
    export TEST_REPO="$PWD/repo"
    export TEST_SETUP=${../lib}/setup.sh
    export TEST_IDENTITY=${../fixtures/admin.asc}
    bash ${./assertions.sh}
    touch $out
  ''
