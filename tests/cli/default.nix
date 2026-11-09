{ pkgs, deploy }:
let
  inherit (pkgs)
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
    runCommand
    ;
in
runCommand "deploy-cli-e2e"
  {
    nativeBuildInputs = [
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
    printf '%s\n' 'experimental-features = nix-command flakes' 'substituters =' 'flake-registry =' >"$XDG_CONFIG_HOME/nix/nix.conf"
    cp ${./flake.nix} repo/flake.nix
    substituteInPlace repo/flake.nix --replace-fail '@system@' '${pkgs.stdenv.hostPlatform.system}'
    export TEST_REPO="$PWD/repo"
    export TEST_SETUP=${../lib/setup.sh}
    bash ${./assertions.sh}
    touch $out
  ''
