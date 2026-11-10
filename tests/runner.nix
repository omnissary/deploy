{ pkgs }:
let
  inherit (pkgs) runCommand;
in
runCommand "deploy-test-runner"
  {
    nativeBuildInputs = with pkgs; [ python3 ];
  }
  ''
    cp ${./run.py} run.py
    cp ${./test_run.py} test_run.py
    python3 -m unittest -v test_run
    touch $out
  ''
