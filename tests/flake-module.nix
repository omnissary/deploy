{ inputs, ... }:
{
  transposition.testSuites = { };
  perSystem =
    {
      config,
      pkgs,
      lib,
      ...
    }:
    let
      inherit (builtins) attrNames attrValues;
      inherit (lib)
        assertMsg
        concatLists
        length
        mapAttrs
        mergeAttrsList
        mkOption
        types
        unique
        ;
      suites = import ./. {
        inherit pkgs;
        deploy = config.packages.default;
        disko = inputs.omnixiah.inputs.disko;
      };
      names = concatLists (attrValues config.testSuites);
    in
    {
      options.testSuites = mkOption {
        type = types.attrsOf (types.listOf types.str);
        readOnly = true;
        description = "Enabled check names grouped by test suite.";
      };
      config = {
        testSuites = mapAttrs (_: attrNames) suites;
        checks =
          assert assertMsg (
            inputs.omnixiah.inputs.deploy.outPath == inputs.self.outPath
          ) "omnixiah must use the root deploy checkout";
          assert assertMsg (length names == length (unique names)) "Test names must be unique across suites";
          mergeAttrsList (attrValues suites);
      };
    };
}
