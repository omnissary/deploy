path:
let
  inherit (builtins) appendContext listToAttrs;
in
appendContext path (listToAttrs [
  {
    name = path;
    value.path = true;
  }
])
