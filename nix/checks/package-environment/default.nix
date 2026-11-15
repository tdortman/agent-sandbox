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
  argsOnly = wrap { launchHook.sandboxed = ""; };
  # Exercise the dynamic launch path without involving the filesystem broker.
  arm = pkgs.writeShellScriptBin "agent-sandbox-fs-arm" ''
    test "$1" = -- || exit 1
    shift
    exec "$@"
  '';
  customPrefix = wrap { unsafeAliasPrefix = "host-"; };
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
  unchanged = wrap {
    launchArgs = {
      sandboxed = [ ];
      unsandboxed = [ ];
    };

    launchHook = {
      sandboxed = "";
      unsandboxed = "";
    };
  };
  unsafeOnly = wrap {
    launchArgs.sandboxed = [ ];
    launchHook.sandboxed = "";
  };
  wrap =
    extra:
    let
      defaults = {
        package = probe;
        commonPkgs = [ pkgs.coreutils ];
        exposeWorkingDirectory = false;

        launchArgs = {
          sandboxed = [
            "--fixed"
            "two fixed words"
            ""
            "*"
            "it's $OMP_TEST_OTHER; $(exit 99)"
          ];

          unsandboxed = [ "--host-only" ];
        };

        launchHook = {
          sandboxed = ''
            unset XDG_DATA_HOME
            export LD_LIBRARY_PATH="${
              lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ]
            }''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            export OMP_TEST_HOOK="$(printf '%s' "it's $OMP_TEST_OTHER")"
          '';

          unsandboxed = "export OMP_TEST_OTHER=host-only";
        };
      };
    in
    sandbox.mkWrapPackage pkgs (
      defaults
      // extra
      // {
        launchArgs = defaults.launchArgs // (extra.launchArgs or { });
        launchHook = defaults.launchHook // (extra.launchHook or { });
      }
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

    def check(binary, xdg, token, *, inherited=True, hooked=True, fixed=True, unsafe=False):
        env = ["env", "OMP_TEST_OTHER=preserved", "GH_TOKEN=test-credential"]
        if inherited:
            env += ["XDG_DATA_HOME=/home/tester/data with spaces", "LD_LIBRARY_PATH=/custom/library path"]
        command = shlex.join(["runuser", "-u", "tester", "--", *env, binary, "two words", "", "*"])
        status, output = machine.execute(command)
        assert status == 23, (binary, status, output)
        library_path = "${lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib ]}" if hooked else ""
        if inherited:
            library_path += (":" if library_path else "") + "/custom/library path"
        args = ["<--fixed>", "<two fixed words>", "<>", "<*>", "<it's $OMP_TEST_OTHER; $(exit 99)>"] if fixed else []
        if unsafe:
            args = ["<--host-only>"]
        assert output.splitlines() == [xdg, "host-only" if unsafe else "preserved", token, library_path or "unset", "it's preserved" if hooked else "unset", *args, "<two words>", "<>", "<*>"], (binary, output)

    for package in ["${static}", "${dynamic}"]:
        check(package + "/bin/env-probe", "unset", "unset")
        check(package + "/bin/sandboxed-env-probe", "unset", "unset")
        check(package + "/bin/unsafe-env-probe", "/home/tester/data with spaces", "test-credential", hooked=False, unsafe=True)
        check(package + "/bin/env-probe", "unset", "unset", inherited=False)

    check("${argsOnly}/bin/env-probe", "/home/tester/data with spaces", "unset", hooked=False)
    check("${argsOnly}/bin/unsafe-env-probe", "/home/tester/data with spaces", "test-credential", hooked=False, unsafe=True)
    check("${unchanged}/bin/env-probe", "/home/tester/data with spaces", "unset", hooked=False, fixed=False)
    check("${unchanged}/bin/unsafe-env-probe", "/home/tester/data with spaces", "test-credential", hooked=False, fixed=False)
    check("${unsafeOnly}/bin/env-probe", "/home/tester/data with spaces", "unset", hooked=False, fixed=False)
    check("${unsafeOnly}/bin/unsafe-env-probe", "/home/tester/data with spaces", "test-credential", hooked=False, unsafe=True)
    check("${nonReplacing}/bin/env-probe", "/home/tester/data with spaces", "test-credential", hooked=False, unsafe=True)
    check("${nonReplacing}/bin/sandboxed-env-probe", "unset", "unset")
    check("${alternate}/bin/alternate", "unset", "unset")
    check("${alternate}/bin/unsafe-alternate", "/home/tester/data with spaces", "test-credential", hooked=False, unsafe=True)
    check("${customPrefix}/bin/env-probe", "unset", "unset")
    check("${customPrefix}/bin/host-env-probe", "/home/tester/data with spaces", "test-credential", hooked=False, unsafe=True)
  '';
}
