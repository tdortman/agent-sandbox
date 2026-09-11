{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e) baseNode module staticPackages;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-filesystem-static";
  node.specialArgs = { inherit inputs; };

  nodes.static =
    _:
    baseNode
    // {
      imports = [ module ];

      agent-sandbox = {
        enable = true;
        packages = staticPackages;
        readonlyDirs = [ "/var/lib/agent-sandbox-test/global-readonly-dir" ];
        readonlyFiles = [ "/var/lib/agent-sandbox-test/global-readonly-file" ];
        readwriteDirs = [ "/var/lib/agent-sandbox-test/global-readwrite-dir" ];
        readwriteFiles = [ "/var/lib/agent-sandbox-test/global-readwrite-file" ];
        sudoPolicy = "deny";
      };
    };

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

    for node in [static]:
        node.wait_for_unit("multi-user.target")

    # Static bubblewrap mounts: read-only directory/file, writable directory,
    # unlisted paths, working-directory opt-out, blocked credentials, and
    # wrapper naming.
    static.succeed("stat -c '%a %U' /var/lib/agent-sandbox-test/readwrite-file | grep -q '644 sandbox'")
    sandbox_shell(static, "sandbox-static-no-cwd-bash", "test ! -e /run/wrappers/bin/sudo")
    static.succeed("runuser -u sandbox -- test -w /var/lib/agent-sandbox-test/readwrite-file")
    sandbox_shell(static, "sandbox-static-bash", "cat /var/lib/agent-sandbox-test/readonly-file | grep -q marker")
    sandbox_shell(static, "sandbox-static-bash", "echo changed > /var/lib/agent-sandbox-test/readonly-file", expect_success=False)
    sandbox_shell(static, "sandbox-static-bash", "test -f /var/lib/agent-sandbox-test/readonly-dir/marker")
    sandbox_shell(static, "sandbox-static-bash", "touch /var/lib/agent-sandbox-test/readonly-dir/blocked", expect_success=False)
    sandbox_shell(static, "sandbox-static-bash", "test ! -e /var/lib/agent-sandbox-test/dynamic-unlisted")
    sandbox_shell(static, "sandbox-static-bash", "grep -q home-readonly-marker ~/sandbox-home-readonly")
    sandbox_shell(static, "sandbox-static-bash", "echo changed > ~/sandbox-home-readonly", expect_success=False)
    sandbox_shell(static, "sandbox-static-bash", "touch ~/sandbox-readwrite/created")
    sandbox_shell(static, "sandbox-static-bash", "test -f ~/sandbox-readwrite/created")
    sandbox_shell(static, "sandbox-static-bash", "opts=$(findmnt -no OPTIONS -T /var/lib/agent-sandbox-test/readwrite-file); [[ ,$opts, == *,rw,* ]]")
    sandbox_shell(static, "sandbox-static-bash", "printf changed > /var/lib/agent-sandbox-test/readwrite-file")
    sandbox_shell(static, "sandbox-static-bash", "grep -q changed /var/lib/agent-sandbox-test/readwrite-file")
    sandbox_shell(static, "sandbox-static-bash", "grep -q global-readonly-dir-marker /var/lib/agent-sandbox-test/global-readonly-dir/marker")
    sandbox_shell(static, "sandbox-static-bash", "touch /var/lib/agent-sandbox-test/global-readonly-dir/blocked", expect_success=False)
    sandbox_shell(static, "sandbox-static-bash", "grep -q global-readonly-file-marker /var/lib/agent-sandbox-test/global-readonly-file")
    sandbox_shell(static, "sandbox-static-bash", "printf changed >/var/lib/agent-sandbox-test/global-readonly-file", expect_success=False)
    sandbox_shell(static, "sandbox-static-bash", "touch /var/lib/agent-sandbox-test/global-readwrite-dir/created")
    sandbox_shell(static, "sandbox-static-bash", "printf changed >/var/lib/agent-sandbox-test/global-readwrite-file")
    static.succeed("test -f /var/lib/agent-sandbox-test/global-readwrite-dir/created")
    static.succeed("grep -q changed /var/lib/agent-sandbox-test/global-readwrite-file")
    sandbox_shell(
        static,
        "sandbox-static-options-bash",
        "grep -q runtime-readonly-marker /run/agent-sandbox-test-runtime/marker && test \"$AGENT_SANDBOX_EXTRA_BWRAP\" = covered && test -z \"$CUSTOM_SECRET\"",
        env=("env", "CUSTOM_SECRET=secret"),
    )
    sandbox_shell(static, "sandbox-static-options-bash", "touch /run/agent-sandbox-test-runtime/blocked", expect_success=False)
    sandbox_shell(
        static,
        "sandbox-static-bash",
        "test -z \"$AWS_SECRET_ACCESS_KEY\" && test -z \"$OPENAI_API_KEY\"",
        env=("env", "AWS_SECRET_ACCESS_KEY=secret", "OPENAI_API_KEY=secret"),
    )
    sandbox_shell(static, "sandbox-static-bash", "test -c /dev/agent-sandbox-test-device && dd if=/dev/agent-sandbox-test-device of=/dev/null bs=1 count=1 status=none")
    sandbox_shell(
        static,
        "sandbox-static-no-cwd-bash",
        'test ! -e "$PWD/marker"',
        cwd="/home/user/sandbox-cwd",
    )
    sandbox_shell(
        static,
        "sandbox-static-bash",
        'grep -q cwd-marker "$PWD/marker"',
        cwd="/home/user/sandbox-cwd",
    )
    sandbox_exec(static, "sandbox-static-curl", "--version")
    assert sandbox_command(static, [ "sandbox-inferred-binary" ]).strip() == "inferred-binary"
    sandbox_shell(static, "unwrapped-sandbox-static-bash", "printf custom-prefix")
    sandbox_shell(static, "sandbox-wrapping-bash", "printf original")
    sandbox_shell(static, "sandboxed-sandbox-wrapping-bash", "printf no-replacement")
  '';
})
