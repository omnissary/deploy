{
  lib,
  buildGoModule,
  symlinkJoin,
  makeWrapper,
  nix,
  openssh,
  cpio,
  ssh-to-age,
  nixos-anywhere,
}:
let
  inherit (lib.fileset)
    gitTracked
    intersection
    toSource
    unions
    ;
  unwrapped = buildGoModule {
    pname = "deploy-unwrapped";
    version = "0.2.0";
    src = toSource {
      root = ./.;
      fileset = intersection (gitTracked ./.) (unions [
        ./main.go
        ./go.mod
        ./go.sum
        ./cmd
        ./internal
        ./vendor
      ]);
    };
    vendorHash = null;
    meta.mainProgram = "deploy";
  };
in
symlinkJoin {
  name = "deploy";
  paths = [ unwrapped ];
  nativeBuildInputs = [ makeWrapper ];
  postBuild = ''
    mkdir -p $out/share/fish/vendor_completions.d $out/nix-support
    ${unwrapped}/bin/deploy fish-completion \
      > $out/share/fish/vendor_completions.d/deploy.fish
    echo 'export XDG_DATA_DIRS='"$out"'/share''${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}' \
      > $out/nix-support/setup-hook

    wrapProgram $out/bin/deploy \
      --prefix PATH : ${
        lib.makeBinPath [
          nix
          openssh
          cpio
          ssh-to-age
          nixos-anywhere
        ]
      }
  '';
  meta = with lib; {
    description = "NixOS machine deployment CLI";
    mainProgram = "deploy";
    license = licenses.mit;
  };
}
