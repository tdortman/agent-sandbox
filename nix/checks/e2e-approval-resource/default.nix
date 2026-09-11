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
    installPolicy
    mkBash
    module
    resourceApprovalPolicy
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-approval-resource";
  node.specialArgs = { inherit inputs; };

  nodes.resource-approval =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (installPolicy resourceApprovalPolicy) {
        imports = [ module ];

        agent-sandbox = {
          enable = true;

          gates = {
            filesystem.enable = true;
            resources.enable = true;
          };

          packages = [
            (mkBash "sandbox-resource-approve-bash" {
              extraPkgs = commonExtraPkgs;
            })
          ];

          policy = {
            dbus.enable = false;
            uiBackend = "none";
          };
        };

        services.dbus.enable = true;

        systemd.services.agent-sandbox-vm-resource-pending-server = {
          after = [ "agent-sandbox-vm-policy.service" ];
          wantedBy = [ "multi-user.target" ];

          serviceConfig = {
            ExecStart = "${pkgs.socat}/bin/socat UNIX-LISTEN:/run/agent-sandbox-test/pending.sock,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
            Restart = "on-failure";
            RuntimeDirectory = "agent-sandbox-test";
            User = "sandbox";
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

    for node in [resource_approval]:
        node.wait_for_unit("multi-user.target")

    # Resource pending attribution: an unlisted socket connect pends with
    # the package attributed, and a project_package approval persists the
    # rule to the package-specific project file.
    resource_approval.wait_for_unit("agent-sandbox-vm-resource-pending-server.service")
    resource_approval.succeed("test -S /run/agent-sandbox-test/pending.sock")

    def resource_bg(script):
        inner = f"cd /home/user && {shlex.join(['sandbox-resource-approve-bash', '-c', script])}"
        detached = (
            "nohup runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 "
            f"sh -c {shlex.quote(inner)} </dev/null >/tmp/resource-pending.out 2>&1 &"
        )
        return command("sh", "-c", detached)

    resource_approval.succeed(
        resource_bg("printf pending-ok | socat -T 30 - UNIX-CONNECT:/run/agent-sandbox-test/pending.sock")
    )
    resource_approval.wait_until_succeeds(
        "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q '/run/agent-sandbox-test/pending.sock'"
    )
    # The pending carries the package attribution.
    resource_approval.succeed(
        "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"resource\" {print $5}' | grep -q 'sandbox-resource-approve-bash'"
    )
    pending_res_id = resource_approval.succeed(
        "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"resource\" {print $1; exit}'"
    ).strip()
    resource_approval.succeed(
        f"runuser -u sandbox -- agent-sandbox-approve approve {pending_res_id} project_package"
    )
    resource_approval.wait_until_succeeds("grep -q pending-ok /tmp/resource-pending.out")
    resource_approval.succeed(
        "test -f /home/user/.agent-sandbox/packages/sandbox-resource-approve-bash.json"
    )
  '';
})
