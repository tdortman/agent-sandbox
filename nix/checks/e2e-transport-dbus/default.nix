{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e)
    baseNode
    commonExtraPkgs
    dbusPolicy
    installPolicy
    mkBash
    module
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-transport-dbus";
  node.specialArgs = { inherit inputs; };

  nodes.dbus =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (installPolicy dbusPolicy) {
        imports = [ module ];

        agent-sandbox = {
          enable = true;

          gates = {
            filesystem.enable = true;
            resources.enable = true;
          };

          packages = [
            (mkBash "sandbox-dbus-bash" {
              extraPkgs = commonExtraPkgs;
            })
          ];

          policy = {
            dbus = {
              enable = true;

              declarativeAllow =
                map
                  (bus: {
                    comment = "VM module serialization allow";

                    target = {
                      inherit bus;
                      destination = "org.freedesktop.DBus";
                      interface = "org.freedesktop.DBus";
                      member = "ListNames";
                      messageKind = "method_call";
                      objectPath = "/org/freedesktop/DBus";
                      signature = "";
                    };
                  })
                  [
                    "session"
                    "system"
                  ];

              declarativeDeny =
                map
                  (bus: {
                    comment = "VM module serialization deny";

                    target = {
                      inherit bus;
                      destination = "org.freedesktop.DBus";
                      interface = "org.freedesktop.DBus";
                      member = "GetId";
                      messageKind = "method_call";
                      objectPath = "/org/freedesktop/DBus";
                      signature = "";
                    };
                  })
                  [
                    "session"
                    "system"
                  ];

              socketDirectory = "/var/lib/agent-sandbox-test/dbus-runtime";
              upstreamAddress = "unix:path=/run/user/1000/bus";
            };

            interactiveApproval = false;
            uiBackend = "none";
          };
        };

        services.dbus.enable = true;
      }
    );

  testScript = ''
    import shlex

    def command(*args):
        return shlex.join(str(arg) for arg in args)

    def sandbox_command(node, args, *, wrapper=(), expect_success=True):
        line = command("runuser", "-u", "sandbox", "--", *wrapper, *args)
        check = node.succeed if expect_success else node.fail
        return check(line, timeout=60)

    def sandbox_shell(node, package, script, *, wrapper=(), cwd=None, env=(), expect_success=True):
        argv = [*env, package, "-c", script]
        if cwd is not None:
            argv = ["sh", "-c", f"cd {shlex.quote(cwd)} && exec {shlex.join(argv)}"]
        return sandbox_command(
            node,
            argv,
            wrapper=wrapper,
            expect_success=expect_success,
        )

    def sandbox_exec(node, package, *args, wrapper=(), expect_success=True):
        return sandbox_command(node, [package, *args], wrapper=wrapper, expect_success=expect_success)

    def check_loopback_bridge(node, package, wrapper=()):
        node.wait_for_unit("agent-sandbox-loopback.service")
        node.wait_for_unit("agent-sandbox-vm-loopback-host.service")
        node.wait_for_unit("agent-sandbox-vm-loopback-sandbox.service")
        node.wait_for_unit("agent-sandbox-vm-loopback6-host.service")
        node.wait_for_unit("agent-sandbox-vm-loopback6-sandbox.service")
        node.wait_for_unit("agent-sandbox-vm-loopback-udp-host.service")
        node.wait_for_unit("agent-sandbox-vm-loopback-udp-sandbox.service")
        node.wait_for_unit("agent-sandbox-vm-loopback-udp6-host.service")
        node.wait_for_unit("agent-sandbox-vm-loopback-udp6-sandbox.service")
        node.succeed("curl --fail --silent --max-time 5 http://127.0.0.1:18089/ >/dev/null")
        node.succeed("curl --fail --silent --max-time 5 http://127.0.0.1:18090/ >/dev/null")
        sandbox_shell(node, package, "curl --fail --silent --max-time 5 http://127.0.0.1:18089/ >/dev/null", wrapper=wrapper)
        sandbox_shell(node, package, "curl --fail --silent --max-time 5 http://127.0.0.1:18090/ >/dev/null", wrapper=wrapper)
        node.succeed("printf host-udp | timeout 5 ${pkgs.socat}/bin/socat - UDP4:127.0.0.1:18092 | grep -q host-udp")
        node.succeed("printf sandbox-udp | timeout 5 ${pkgs.socat}/bin/socat - UDP4:127.0.0.1:18093 | grep -q sandbox-udp")
        node.succeed("systemctl restart agent-sandbox-vm-loopback-udp-host.service; sleep 0.2")
        sandbox_shell(node, package, "printf host-udp | timeout 5 socat - UDP4:127.0.0.1:18092 | grep -q host-udp", wrapper=wrapper)
        node.succeed("systemctl restart agent-sandbox-vm-loopback-udp-sandbox.service; sleep 0.2")
        sandbox_shell(node, package, "printf sandbox-udp | timeout 5 socat - UDP4:127.0.0.1:18093 | grep -q sandbox-udp", wrapper=wrapper)
        node.succeed("curl --noproxy '*' --fail --silent --max-time 5 'http://[::1]:18089/' >/dev/null")
        node.succeed("curl --noproxy '*' --fail --silent --max-time 5 'http://[::1]:18090/' >/dev/null")
        sandbox_shell(node, package, "curl --noproxy '*' --fail --silent --max-time 5 'http://[::1]:18089/' >/dev/null", wrapper=wrapper)
        sandbox_shell(node, package, "curl --noproxy '*' --fail --silent --max-time 5 'http://[::1]:18090/' >/dev/null", wrapper=wrapper)
        node.succeed("printf host-udp6 | timeout 5 ${pkgs.socat}/bin/socat - 'UDP6:[::1]:18092' | grep -q host-udp6")
        node.succeed("printf sandbox-udp6 | timeout 5 ${pkgs.socat}/bin/socat - 'UDP6:[::1]:18093' | grep -q sandbox-udp6")
        node.succeed("systemctl restart agent-sandbox-vm-loopback-udp6-host.service; sleep 0.2")
        sandbox_shell(node, package, "printf host-udp6 | timeout 5 socat - 'UDP6:[::1]:18092' | grep -q host-udp6", wrapper=wrapper)
        node.succeed("systemctl restart agent-sandbox-vm-loopback-udp6-sandbox.service; sleep 0.2")
        sandbox_shell(node, package, "printf sandbox-udp6 | timeout 5 socat - 'UDP6:[::1]:18093' | grep -q sandbox-udp6", wrapper=wrapper)

    start_all()
    session_wrapper = (
        "env",
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    )

    for node in [dbus]:
        node.wait_for_unit("multi-user.target")

    # D-Bus relay: the configured upstream overrides a bad caller address,
    # both buses enforce capability policy, and raw host socket access is denied.
    dbus.wait_for_unit("agent-sandbox-policy.service")
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -q array",
        wrapper=("env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/missing-bus"),
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Introspectable.Introspect | grep -q org.freedesktop.DBus",
        wrapper=session_wrapper,
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "! dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.GetId",
        wrapper=("env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"),
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.RequestName string:com.example.Sandbox uint32:0",
        wrapper=session_wrapper,
        expect_success=False,
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "! timeout 2 socat - UNIX-CONNECT:/run/dbus/system_bus_socket",
        wrapper=("env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"),
    )

    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -q array",
        wrapper=session_wrapper,
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.GetId 2>&1 | grep -q org.freedesktop.DBus.Error.AccessDenied",
        wrapper=session_wrapper,
    )
  '';
})
