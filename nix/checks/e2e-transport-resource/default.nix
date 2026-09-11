{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e)
    baseNode
    installPolicy
    module
    resourcePackages
    resourcePolicy
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-transport-resource";
  node.specialArgs = { inherit inputs; };

  nodes.resource =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (installPolicy resourcePolicy) {
        imports = [ module ];

        agent-sandbox = {
          enable = true;

          gates = {
            filesystem.enable = true;
            resources.enable = true;
          };

          packages = resourcePackages;

          policy = {
            dbus.enable = false;
            interactiveApproval = false;
            uiBackend = "none";
          };
        };

        services.dbus.enable = true;

        systemd.services = {
          agent-sandbox-vm-resource-denied-server = {
            after = [ "agent-sandbox-vm-resource-server.service" ];
            requires = [ "agent-sandbox-vm-resource-server.service" ];
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = "${pkgs.socat}/bin/socat UNIX-LISTEN:/run/agent-sandbox-test/denied.sock,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
              Restart = "on-failure";
              User = "sandbox";
            };
          };

          agent-sandbox-vm-resource-server = {
            after = [ "agent-sandbox-vm-policy.service" ];
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = "${pkgs.socat}/bin/socat UNIX-LISTEN:/run/agent-sandbox-test/echo.sock,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
              Restart = "on-failure";
              RuntimeDirectory = "agent-sandbox-test";
              User = "sandbox";
            };
          };
        };
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

    for node in [resource]:
        node.wait_for_unit("multi-user.target")

    # Resource gates distinguish permitted Unix-socket connect/send and
    # device opens from denied host IPC sockets.
    resource.wait_for_unit("agent-sandbox-policy.service")
    resource.wait_for_unit("agent-sandbox-vm-resource-server.service")
    resource.wait_for_unit("agent-sandbox-vm-resource-denied-server.service")
    resource.succeed("test -S /run/agent-sandbox-test/echo.sock && test -S /run/agent-sandbox-test/denied.sock")
    resource.succeed("test -c /dev/agent-sandbox-test-device && test -c /dev/agent-sandbox-denied-device")
    sandbox_shell(resource, "sandbox-resource-bash", "printf resource-ok | socat -T 2 - UNIX-CONNECT:/run/agent-sandbox-test/echo.sock | grep -q resource-ok")
    sandbox_shell(resource, "sandbox-resource-bash", "printf blocked | socat -T 2 - UNIX-CONNECT:/run/agent-sandbox-test/denied.sock | grep -q blocked", expect_success=False)
    sandbox_shell(resource, "sandbox-resource-bash", "dd if=/dev/agent-sandbox-test-device of=/dev/null bs=1 count=1 status=none")
    sandbox_shell(resource, "sandbox-resource-bash", "dd if=/dev/agent-sandbox-denied-device of=/dev/null bs=1 count=1 status=none", expect_success=False)
  '';
})
