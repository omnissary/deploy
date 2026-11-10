{ pkgs }:
let
  inherit (pkgs) fetchurl gotools;
in
{
  gotools = gotools.overrideAttrs (old: {
    patches = (old.patches or [ ]) ++ [
      (fetchurl {
        url = "https://patch-diff.githubusercontent.com/raw/golang/tools/pull/554.patch";
        hash = "sha256-I3pQSDi1JYRZ55SDtNXoA3u6Aqd3qrx+PBeLPe4EGQE=";
      })
    ];
  });
}
