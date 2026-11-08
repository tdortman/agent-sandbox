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
  name = "e2e-policyd-restart";
  node.specialArgs = { inherit inputs; };

  nodes.dynamic =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (installPolicy dynamicPolicy) {
        imports = [ module ];

        agent-sandbox = {
          enable = true;

          gates = {
            filesystem.enable = true;
            syscalls.enable = true;
          };

          network = {
            enable = true;
            dnsForwardTarget = "169.254.100.1:5353";
          };

          packages = dynamicPackages;

          policy = {
            interactiveApproval = false;
            uiBackend = "none";
          };
        };

        boot.kernel.sysctl."kernel.yama.ptrace_scope" = 1;
      }
    );

  testScript = ''
    import re
    import shlex

    def command(*args):
        return shlex.join(str(arg) for arg in args)

    mutations = "/var/lib/agent-sandbox-test/dynamic-mutations"
    fsmon_pattern = "^/nix/store/[^ ]*/bin/agent-sandbox-fsmon"
    sandbox_socket = "/run/agent-sandbox/sandbox-policy.sock"

    start_all()
    dynamic.wait_for_unit("multi-user.target")
    dynamic.wait_for_unit("agent-sandbox-policy.socket")
    dynamic.wait_for_unit("agent-sandbox-policy.service")

    # One long-lived sandbox, driven through a fifo so every probe runs in the
    # same sandbox before and after the restart.
    dynamic.succeed("mkfifo -m 0666 /tmp/restart-input")
    script = (
        "while read -r token operation first second; do "
        "case \"$operation\" in "
        "create) printf created > \"$first\";; "
        "rename) mv \"$first\" \"$second\";; "
        "remove) rm \"$first\";; "
        "read) cat \"$first\" >/dev/null;; "
        "esac; "
        "status=$?; printf '%s %s\\n' \"$token\" \"$status\"; done"
    )
    launch = command("runuser", "-u", "sandbox", "--", "sandbox-dynamic-bash", "-c", script)
    dynamic.succeed(command(
        "systemd-run", "--unit=restart-live", "--service-type=exec",
        "--setenv=PATH=/run/wrappers/bin:/run/current-system/sw/bin",
        "sh", "-c", "exec " + launch + " < /tmp/restart-input > /tmp/restart-output 2>/tmp/restart-errors",
    ))
    # Keep the pipe open across probes.
    dynamic.succeed("sh -c 'exec 3>/tmp/restart-input; sleep 600' >/dev/null 2>&1 &")
    tokens = iter(range(1000))

    def probe(operation, first, second="-", allowed=True):
        token = str(next(tokens))
        dynamic.succeed(command("printf", "%s\\n", " ".join([token, operation, first, second])) + " > /tmp/restart-input")
        try:
            dynamic.wait_until_succeeds(command("grep", "-q", "^" + token + " ", "/tmp/restart-output"), timeout=60)
        except Exception:
            print(dynamic.succeed("cat /tmp/restart-errors"))
            raise
        result = dynamic.succeed(command("grep", "^" + token + " ", "/tmp/restart-output")).split()[1]
        assert (result == "0") == allowed, f"{operation} {first}: exit {result}"

    def mutate_and_check(name):
        created = mutations + "/" + name
        renamed = created + "-renamed"
        probe("create", created)
        dynamic.succeed(command("test", "-f", created))
        probe("rename", created, renamed)
        dynamic.succeed(command("test", "!", "-e", created) + " && " + command("test", "-f", renamed))
        probe("remove", renamed)
        dynamic.succeed(command("test", "!", "-e", renamed))

    mutate_and_check("before-restart")
    probe("read", "/var/lib/agent-sandbox-test/dynamic-read")
    probe("read", "/var/lib/agent-sandbox-test/dynamic-unlisted", allowed=False)

    fsmon_pid = dynamic.succeed(command("pgrep", "-f", fsmon_pattern)).split()
    assert len(fsmon_pid) == 1, f"expected exactly one fsmon, got {fsmon_pid}"
    fsmon_pid = fsmon_pid[0]
    socket_inode = dynamic.succeed(command("stat", "-c", "%i", sandbox_socket)).strip()

    dynamic.succeed("systemctl restart agent-sandbox-policy.service")
    dynamic.wait_for_unit("agent-sandbox-policy.service")

    # The socket inode the sandbox bind-mounted is still the live one, and the
    # sandbox's own monitor is still running.
    assert dynamic.succeed(command("stat", "-c", "%i", sandbox_socket)).strip() == socket_inode
    dynamic.succeed(command("kill", "-0", fsmon_pid))
    assert dynamic.succeed(command("pgrep", "-f", fsmon_pattern)).split() == [fsmon_pid]

    # The same sandbox keeps mutating and stays confined.
    mutate_and_check("after-restart")
    probe("read", "/var/lib/agent-sandbox-test/dynamic-read")
    probe("read", "/var/lib/agent-sandbox-test/dynamic-unlisted", allowed=False)
    dynamic.succeed(command("kill", "-0", fsmon_pid))

    # A sandbox launched after the restart works against the new policyd.
    dynamic.succeed(command(
        "runuser", "-u", "sandbox", "--", "sandbox-dynamic-bash", "-c",
        "printf fresh > " + mutations + "/fresh && mv " + mutations + "/fresh " + mutations + "/fresh-renamed && rm " + mutations + "/fresh-renamed",
    ))
    dynamic.succeed(command("test", "!", "-e", mutations + "/fresh-renamed"))

    # The node runs the network-mode launcher: no PID namespace, so only
    # fsmon's scope kill stops what a finished sandbox leaves behind.
    session_wrapper = (
        "env",
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    )

    def fsmon_pids():
        return set(dynamic.succeed("pgrep -f '" + fsmon_pattern + "' || true").split())

    def start_lifetime_sandbox(tag, duration, script):
        before = fsmon_pids()
        launch = command("runuser", "-u", "sandbox", "--", *session_wrapper, "sandbox-dynamic-bash", "-c", script)
        dynamic.succeed(command(
            "systemd-run", "--unit=lifetime-" + tag, "--service-type=exec",
            "--setenv=PATH=/run/wrappers/bin:/run/current-system/sw/bin",
            "sh", "-c", "exec " + launch + " </dev/null >/dev/null 2>/tmp/lifetime-" + tag + "-errors",
        ))
        match = "'^sleep " + str(duration) + "$'"
        try:
            dynamic.wait_until_succeeds("pgrep -u sandbox -f " + match, timeout=60)
        except Exception:
            print(dynamic.succeed("cat /tmp/lifetime-" + tag + "-errors"))
            raise
        grandchild = dynamic.succeed("pgrep -u sandbox -f " + match).split()[0]
        cgroup = dynamic.succeed("sed -n 's/^0:://p' /proc/" + grandchild + "/cgroup").strip()
        scope = re.fullmatch(r".*/agent-sandbox-(\d+)_\d+\.scope", cgroup)
        assert scope, f"sandbox is not in its own scope: {cgroup}"
        launcher = scope.group(1)
        argv = dynamic.succeed("tr '\\0' '\\n' < /proc/" + launcher + "/cmdline").split()
        assert "--unshare-user" in argv and "--unshare-pid" not in argv, f"not the network-mode launcher: {argv}"
        started = fsmon_pids() - before
        assert len(started) == 1, f"expected one new fsmon, got {started}"
        return {
            "grandchild": grandchild,
            "cgroup": cgroup,
            "launcher": launcher,
            "fsmon": started.pop(),
        }

    def assert_sandbox_gone(sandbox):
        # Reaping fsmon is policyd's job, so a zombie fsmon fails this too.
        dynamic.wait_until_fails("test -e /proc/" + sandbox["grandchild"], timeout=5)
        dynamic.wait_until_fails("test -e /proc/" + sandbox["fsmon"], timeout=5)
        dynamic.wait_until_fails("test -e /sys/fs/cgroup" + sandbox["cgroup"], timeout=10)

    # The launcher is killed: the broker dies with bwrap and the agent keeps a
    # seccomp filter without a listener.
    killed = start_lifetime_sandbox("kill", 7001, "setsid sleep 7001 & exec sleep 7000")
    dynamic.succeed("kill -KILL " + killed["launcher"])
    assert_sandbox_gone(killed)
    dynamic.fail("pgrep -u sandbox -f '^sleep 700[01]$'")

    # The agent exits with a detached grandchild still running; the launcher
    # reports the agent's own exit status, not the scope kill's.
    go_file = mutations + "/lifetime-go"
    dynamic.succeed("rm -f " + go_file)
    exited = start_lifetime_sandbox(
        "exit", 7002,
        "setsid sleep 7002 & while [ ! -e " + go_file + " ]; do sleep 0.2; done; exit 7",
    )
    dynamic.succeed("touch " + go_file)
    assert_sandbox_gone(exited)
    dynamic.wait_until_succeeds("systemctl show -p ActiveState --value lifetime-exit.service | grep -qx failed", timeout=10)
    status = dynamic.succeed("systemctl show -p ExecMainStatus --value lifetime-exit.service").strip()
    assert status == "7", f"agent exit status lost: {status}"
    dynamic.succeed("rm -f " + go_file)
  '';
})
