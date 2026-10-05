{ pkgs, inputs, ... }:
let
  sgconfig = pkgs.writeText "no-tuple-type-sgconfig.yml" ''
    ruleDirs:
      - ${./rules}
    testConfigs:
      - testDir: ${./rule-tests}
  '';
in
pkgs.runCommand "no-tuple-type" { nativeBuildInputs = [ pkgs.ast-grep ]; } ''
  ast-grep test --config ${sgconfig} --skip-snapshot-tests
  ast-grep scan --config ${sgconfig} --report-style short ${inputs.self}/crates
  touch $out
''
