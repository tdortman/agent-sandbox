{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  alternate = wrap {
    package = pkgs.symlinkJoin {
      name = "alternate-probe";
      paths = [ probe ];
      postBuild = "ln -s $out/bin/env-probe $out/bin/alternate";
      meta.mainProgram = "env-probe";
    };

    binary = "alternate";
  };
  # Exercise the dynamic launch path without involving the filesystem broker.
  arm = pkgs.writeShellScriptBin "agent-sandbox-fs-arm" ''
    test "$1" = -- || exit 1
    shift
    exec "$@"
  '';
  dynamic = wrap { fsArmPkg = arm; };
  nonReplacing = wrap { replaceOriginalBinary = false; };
  probe = pkgs.writeShellScriptBin "env-probe" ''
    printf '%s\n' "''${XDG_DATA_HOME-unset}" "''${OMP_TEST_OTHER-unset}" "''${GH_TOKEN-unset}" "''${LD_LIBRARY_PATH-unset}" "''${OMP_TEST_HOOK-unset}"
    if [ "''${OMP_TEST_HOOK-unset}" != unset ]; then
      test -r "''${LD_LIBRARY_PATH%%:*}/libstdc++.so.6" || exit 24
    fi
    printf '<%s>\n' "$@"
    exit 23
  '';
  sandbox = import ../../modules/nixos/agent-sandbox/lib.nix {
    inherit lib;
    inherit (inputs) jail-nix;
  };
  static = wrap { };
  unchanged = wrap { launchHook = ""; };
  wrap =
    extra:
    sandbox.mkWrapPackage pkgs (
      {
        package = probe;
        commonPkgs = [ pkgs.coreutils ];
        exposeWorkingDirectory = false;

        launchHook = ''
          unset XDG_DATA_HOME
          export LD_LIBRARY_PATH="${
            lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ]
          }''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          export OMP_TEST_HOOK="$(printf '%s' "it's $OMP_TEST_OTHER")"
        '';
      }
      // extra
    );
in
pkgs.testers.runNixOSTest {
  name = "package-environment";

  nodes.machine = {
    users.users.tester = {
      isNormalUser = true;
      uid = 1000;
    };

    virtualisation.memorySize = 1024;
  };

  testScript = ''
    import shlex

    start_all()
    machine.wait_for_unit("multi-user.target")

    def check(binary, xdg, token, *, inherited=True, hooked=True):
        env = ["env", "OMP_TEST_OTHER=preserved", "GH_TOKEN=test-credential"]
        if inherited:
            env += ["XDG_DATA_HOME=/home/tester/data with spaces", "LD_LIBRARY_PATH=/custom/library path"]
        command = shlex.join(["runuser", "-u", "tester", "--", *env, binary, "two words", "", "*"])
        status, output = machine.execute(command)
        assert status == 23, (binary, status, output)
        library_path = "${lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ]}" if hooked else ""
        if inherited:
            library_path += (":" if library_path else "") + "/custom/library path"
        assert output.splitlines() == [xdg, "preserved", token, library_path or "unset", "it's preserved" if hooked else "unset", "<two words>", "<>", "<*>"], (binary, output)

    for package in ["${static}", "${dynamic}"]:
        check(package + "/bin/env-probe", "unset", "unset")
        check(package + "/bin/sandboxed-env-probe", "unset", "unset")
        check(package + "/bin/unsafe-env-probe", "unset", "test-credential")
        check(package + "/bin/env-probe", "unset", "unset", inherited=False)

    check("${unchanged}/bin/env-probe", "/home/tester/data with spaces", "unset", hooked=False)
    check("${unchanged}/bin/unsafe-env-probe", "/home/tester/data with spaces", "test-credential", hooked=False)
    check("${nonReplacing}/bin/env-probe", "unset", "test-credential")
    check("${nonReplacing}/bin/sandboxed-env-probe", "unset", "unset")
    check("${alternate}/bin/alternate", "unset", "unset")
    check("${alternate}/bin/unsafe-alternate", "unset", "test-credential")
  '';
}
