{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e)
    baseNode
    dynamicPackages
    dynamicPolicy
    installPolicy
    module
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-filesystem-dynamic";
  node.specialArgs = { inherit inputs; };

  nodes.dynamic =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (installPolicy dynamicPolicy) {
        imports = [ module ];

        agent-sandbox = {
          enable = true;
          gates.filesystem.enable = true;
          packages = dynamicPackages;

          policy = {
            exportedNix = "/var/lib/agent-sandbox/exported-policy.nix";
            interactiveApproval = false;
            uiBackend = "none";
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

    for node in [dynamic]:
        node.wait_for_unit("multi-user.target")

    # Dynamic filesystem approval: static store access remains available,
    # unlisted host files are denied, and configured masks hide contents.
    dynamic.wait_for_unit("agent-sandbox-policy.service")
    # nfq persists the session context file during a previous sandbox run,
    # so a fresh launch always finds it present. fsmon must tolerate that:
    # reading the file after marking sandbox mounts would deadlock on its
    # own fanotify permission event, so every launch below is a regression
    # test for the second-launch hang.
    dynamic.succeed(
        "mkdir -p /run/agent-sandbox && printf '%s\\n' '{\"cwd\": \"/home/sandbox\", \"home\": \"/home/sandbox\", \"project_root\": \"/home/sandbox\"}' > /run/agent-sandbox/session-context.json"
    )
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -r /nix/store")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "grep -q dynamic-read-marker /var/lib/agent-sandbox-test/dynamic-read")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf changed >/var/lib/agent-sandbox-test/dynamic-read", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf changed > /var/lib/agent-sandbox-test/dynamic-write")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "grep -q changed /var/lib/agent-sandbox-test/dynamic-write")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "! cat /var/lib/agent-sandbox-test/dynamic-denied >/dev/null")
    # Approved mutations are broker-emulated from the captured syscall
    # arguments; denied mutations fail closed and leave every artifact intact.
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf mutation > /var/lib/agent-sandbox-test/dynamic-mutations/rename-source")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "mv /var/lib/agent-sandbox-test/dynamic-mutations/rename-source /var/lib/agent-sandbox-test/dynamic-mutations/renamed")
    dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/rename-source && test -f /var/lib/agent-sandbox-test/dynamic-mutations/renamed")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf dirfd > dirfd-source", cwd="/var/lib/agent-sandbox-test/dynamic-mutations")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "python3 -c 'import os; d = os.open(\".\", os.O_RDONLY | os.O_DIRECTORY); os.rename(\"dirfd-source\", \"dirfd-renamed\", src_dir_fd=d, dst_dir_fd=d); os.close(d)'", cwd="/var/lib/agent-sandbox-test/dynamic-mutations")
    dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/dirfd-source && test -f /var/lib/agent-sandbox-test/dynamic-mutations/dirfd-renamed")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf relative > relative-source", cwd="/var/lib/agent-sandbox-test/dynamic-mutations")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "mv relative-source relative-renamed", cwd="/var/lib/agent-sandbox-test/dynamic-mutations")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "rm relative-renamed", cwd="/var/lib/agent-sandbox-test/dynamic-mutations")
    dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/relative-source && test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/relative-renamed")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln /var/lib/agent-sandbox-test/dynamic-mutations/renamed /var/lib/agent-sandbox-test/dynamic-mutations/hardlink")
    dynamic.succeed("test -f /var/lib/agent-sandbox-test/dynamic-mutations/hardlink")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln -s renamed /var/lib/agent-sandbox-test/dynamic-mutations/symlink")
    dynamic.succeed("test -L /var/lib/agent-sandbox-test/dynamic-mutations/symlink && test \"$(readlink /var/lib/agent-sandbox-test/dynamic-mutations/symlink)\" = renamed")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "truncate -s 0 /var/lib/agent-sandbox-test/dynamic-mutations/renamed")
    dynamic.succeed("test ! -s /var/lib/agent-sandbox-test/dynamic-mutations/renamed")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf ftruncate > /var/lib/agent-sandbox-test/dynamic-mutations/renamed")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "python3 -c 'import os; fd = os.open(\"renamed\", os.O_WRONLY); os.ftruncate(fd, 0); os.close(fd)'", cwd="/var/lib/agent-sandbox-test/dynamic-mutations")
    dynamic.succeed("test ! -s /var/lib/agent-sandbox-test/dynamic-mutations/renamed")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "rm /var/lib/agent-sandbox-test/dynamic-mutations/hardlink")
    dynamic.succeed("test -f /var/lib/agent-sandbox-test/dynamic-mutations/renamed")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "mkdir /var/lib/agent-sandbox-test/dynamic-mutations/directory")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "rmdir /var/lib/agent-sandbox-test/dynamic-mutations/directory")
    dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/directory")
    # Existing-path mkdir attempts return EEXIST without consulting policy.
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "mkdir -p /var/lib/agent-sandbox-test/dynamic-mutations/denied")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf blocked > /var/lib/agent-sandbox-test/dynamic-mutations/rename-denied-source")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "mv /var/lib/agent-sandbox-test/dynamic-mutations/rename-denied-source /var/lib/agent-sandbox-test/dynamic-mutations/denied/renamed", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln /var/lib/agent-sandbox-test/dynamic-mutations/renamed /var/lib/agent-sandbox-test/dynamic-mutations/denied/hardlink", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln -s denied/secret /var/lib/agent-sandbox-test/dynamic-mutations/symlink-to-denied", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "mv /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret /var/lib/agent-sandbox-test/dynamic-mutations/moved-from-denied", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "rm /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "truncate -s 0 /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret", expect_success=False)
    dynamic.succeed("test -f /var/lib/agent-sandbox-test/dynamic-mutations/rename-denied-source")
    dynamic.succeed("test -f /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret")
    dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/denied/renamed")
    dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/denied/hardlink")
    dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/symlink-to-denied")
    dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/moved-from-denied")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -c /etc/agent-sandbox-test/hidden-file")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "! cat /var/lib/agent-sandbox-test/dynamic-unlisted >/dev/null")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -c /var/lib/agent-sandbox-test/hidden-file && ! grep -q 'hidden-file-marker' /var/lib/agent-sandbox-test/hidden-file")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -d ~/sandbox-hidden-dir && test ! -e ~/sandbox-hidden-dir/marker")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf dynamic >/tmp/dynamic-marker")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -d ~/.snapshots && test ! -e ~/.snapshots/marker")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -d /home/.snapshots && test ! -e /home/.snapshots/marker")
    dynamic.succeed("${lib.getExe pkgs.jq} -e . /var/lib/agent-sandbox/exported-policy.json >/dev/null")
    dynamic.succeed("nix-instantiate --eval --strict /var/lib/agent-sandbox/exported-policy.nix >/dev/null")
    sandbox_exec(dynamic, "sandbox-dynamic-curl", "--version")
    sandbox_shell(
        dynamic,
        "sandbox-dynamic-bash",
        "test -z \"$AWS_SECRET_ACCESS_KEY\" && test -z \"$OPENAI_API_KEY\"",
        env=("env", "AWS_SECRET_ACCESS_KEY=secret", "OPENAI_API_KEY=secret"),
    )
  '';
})
