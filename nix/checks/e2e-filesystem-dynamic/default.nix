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

            filesystem.declarativeAllow = [
              {
                access = "read";
                path = "/var/lib/agent-sandbox-test/dynamic-unwritable";
              }
            ];

            interactiveApproval = false;
            uiBackend = "none";
          };
        };

        # The kernel default, pinned: the broker can read only its own
        # descendants' syscall arguments.
        boot.kernel.sysctl."kernel.yama.ptrace_scope" = 1;

        # Read-only superblock fixture for ignore-mark regressions: a tmpfs
        # remounted read-only reports `ro` in its mountinfo super options, so
        # fsmon may install inode ignore marks here. A read-only bind or bare
        # mode bits would still admit aliases through a writable mount.
        systemd.services.agent-sandbox-vm-ro-frozen = {
          before = [ "agent-sandbox-policy.service" ];
          wantedBy = [ "multi-user.target" ];

          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };

          script = ''
            install -d -m 0755 /var/lib/agent-sandbox-test/ro-frozen
            if ! mountpoint -q /var/lib/agent-sandbox-test/ro-frozen; then
              mount -t tmpfs -o size=16m tmpfs /var/lib/agent-sandbox-test/ro-frozen
              printf ro-frozen-marker > /var/lib/agent-sandbox-test/ro-frozen/marker
              chmod 0444 /var/lib/agent-sandbox-test/ro-frozen/marker
              mount -o remount,ro /var/lib/agent-sandbox-test/ro-frozen
            fi
          '';

          path = [ pkgs.util-linux ];
        };
      }
    );

  testScript = ''
    import shlex
    import re
    import json

    def command(*args):
        return shlex.join(str(arg) for arg in args)

    def counter(field, line):
        match = re.search(field + r"=(\d+)", line)
        assert match, f"{field} missing from {line}"
        return int(match.group(1))

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
    # A double-forked daemon stays in the broker's process tree (the broker is
    # its subreaper), so its mutations are still brokered, and it dies with its
    # sandbox instance instead of outliving the seccomp listener.
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "( bash -c 'sleep 0.5; mkdir /var/lib/agent-sandbox-test/dynamic-mutations/daemon-directory' & ); for _ in $(seq 50); do test -d /var/lib/agent-sandbox-test/dynamic-mutations/daemon-directory && exit 0; sleep 0.1; done; exit 1")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "( setsid sleep 300 & )")
    dynamic.fail("pgrep -u sandbox -x sleep")
    # Existing-path mkdir attempts return EEXIST without consulting policy.
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "mkdir -p /var/lib/agent-sandbox-test/dynamic-mutations/denied")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf blocked > /var/lib/agent-sandbox-test/dynamic-mutations/rename-denied-source")
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "mv /var/lib/agent-sandbox-test/dynamic-mutations/rename-denied-source /var/lib/agent-sandbox-test/dynamic-mutations/denied/renamed", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln /var/lib/agent-sandbox-test/dynamic-mutations/renamed /var/lib/agent-sandbox-test/dynamic-mutations/denied/hardlink", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln -s denied/secret /var/lib/agent-sandbox-test/dynamic-mutations/symlink-to-denied", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "mv /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret /var/lib/agent-sandbox-test/dynamic-mutations/moved-from-denied", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "rm /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret", expect_success=False)
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "truncate -s 0 /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret", expect_success=False)
    # A deny nested inside an allowed tree also blocks plain reads: fsmon
    # answers the allowed tree locally, so it must honour the deny as well.
    sandbox_shell(dynamic, "sandbox-dynamic-bash", "! cat /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret >/dev/null")
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
    dynamic.wait_for_unit("agent-sandbox-vm-ro-frozen.service")
    policy_path = "/home/user/.config/agent-sandbox/policy.json"
    policy = json.loads(dynamic.succeed(command("cat", policy_path)))
    frozen = "/var/lib/agent-sandbox-test/ro-frozen/marker"
    mutable = "/var/lib/agent-sandbox-test/dynamic-mutations/warmed"
    alias = "/var/lib/agent-sandbox-test/dynamic-mutations/alias"
    denied_dir = "/var/lib/agent-sandbox-test/dynamic-mutations/denied"
    dynamic.succeed(command("ln", denied_dir + "/secret", alias))
    dynamic.succeed("printf warmed > " + mutable + "; chmod 0666 " + mutable)
    policy["filesystem"]["allow"].append({"path": frozen, "access": "read"})

    def save_policy():
        dynamic.succeed(
            command("printf", "%s", json.dumps(policy)) + " > " + policy_path + ".next && "
            + command("chown", "sandbox:users", policy_path + ".next") + " && "
            + command("mv", policy_path + ".next", policy_path)
        )

    save_policy()
    dynamic.succeed("mkfifo -m 0666 /tmp/fsmon-input")
    script = (
        "while read -r token operation path; do "
        "if [ \"$operation\" = read ]; then cat \"$path\" >/dev/null; "
        "else printf changed >> \"$path\"; fi; "
        "status=$?; printf '%s %s\\n' \"$token\" \"$status\"; done"
    )
    launch = command("runuser", "-u", "sandbox", "--", "sandbox-dynamic-bash", "-c", script)
    dynamic.succeed(command(
        "systemd-run", "--unit=fsmon-live", "--service-type=exec",
        "--setenv=PATH=/run/wrappers/bin:/run/current-system/sw/bin",
        "sh", "-c", "exec " + launch + " < /tmp/fsmon-input > /tmp/fsmon-output 2>/tmp/fsmon-errors",
    ))
    # Keep the pipe open across probes so the same sandbox and monitor survive.
    dynamic.succeed("sh -c 'exec 3>/tmp/fsmon-input; sleep 300' >/dev/null 2>&1 &")
    probe_tokens = iter(range(100))

    def probe(path, operation, allowed):
        token = str(next(probe_tokens))
        dynamic.succeed(command("printf", "%s\\n", token + " " + operation + " " + path) + " > /tmp/fsmon-input")
        try:
            dynamic.wait_until_succeeds(command("grep", "-q", "^" + token + " ", "/tmp/fsmon-output"), timeout=15)
        except Exception:
            print(dynamic.succeed("cat /tmp/fsmon-errors"))
            raise
        result = dynamic.succeed(command("grep", "^" + token + " ", "/tmp/fsmon-output")).split()[1]
        assert (result == "0") == allowed, f"{operation} {path}: exit {result}"

    probe(alias, "read", False)
    probe(alias, "write", False)
    probe(mutable, "read", True)
    probe(mutable, "read", True)
    dynamic.succeed(command("ln", mutable, denied_dir + "/warmed"))
    probe(mutable, "read", False)
    probe(mutable, "write", False)
    probe(frozen, "read", True)
    probe(frozen, "read", True)
    policy["filesystem"]["allow"] = [rule for rule in policy["filesystem"]["allow"] if rule["path"] != frozen]
    save_policy()
    dynamic.sleep(3)
    probe(frozen, "read", False)
    policy["filesystem"]["allow"].append({"path": frozen, "access": "read"})
    save_policy()
    dynamic.sleep(3)
    probe(frozen, "read", True)
    policy["filesystem"]["deny"].append({"path": frozen, "access": "read"})
    save_policy()
    dynamic.sleep(3)
    probe(frozen, "read", False)

    dynamic.succeed("pgrep -f '^/nix/store/[^ ]*/bin/agent-sandbox-fsmon' | xargs -r kill -TERM")
    dynamic.wait_until_succeeds(
        "! pgrep -f '^/nix/store/[^ ]*/bin/agent-sandbox-fsmon'", timeout=60
    )
    counters = dynamic.succeed(
        "journalctl -u agent-sandbox-policy.service --no-pager | grep 'fsmon decisions' | grep 'reason=\"shutdown\"'"
    )
    print(counters)
    added = sum(counter("marks_added", line) for line in counters.splitlines())
    flushed = sum(counter("marks_flushed", line) for line in counters.splitlines())
    assert added > 0, f"no ignore marks were installed: {counters}"
    assert flushed == added, f"flush did not release every mark: {counters}"
  '';
})
