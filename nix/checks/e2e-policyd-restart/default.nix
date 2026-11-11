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
    loopbackServices
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

            declarativeAllow = [
              {
                host = "169.254.100.1";
                port = 18095;
              }
            ];

            dnsForwardTarget = "169.254.100.1:5353";
            loopback.tcpPorts = [ 18089 ];
          };

          packages = dynamicPackages;

          policy = {
            interactiveApproval = false;
            uiBackend = "none";
          };
        };

        boot.kernel.sysctl."kernel.yama.ptrace_scope" = 1;

        # A system update that changes policyd and every unit beneath the
        # sandboxes' network.
        specialisation.changed-policyd.configuration.systemd.services =
          lib.genAttrs
            [
              "agent-sandbox-dns"
              "agent-sandbox-loopback"
              "agent-sandbox-netns"
              "agent-sandbox-policy"
            ]
            (_: {
              environment.AGENT_SANDBOX_TEST_GENERATION = "changed";
            });

        systemd.services = {
          inherit (loopbackServices) agent-sandbox-vm-loopback-host;

          # A TCP echo on the host side of the sandbox veth: a connection a
          # sandbox holds open breaks if a switch rebuilds the namespace.
          agent-sandbox-vm-echo = {
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:18095,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
              Restart = "on-failure";
            };
          };
        };
      }
    );

  testScript = ''
    import re
    import shlex

    def command(*args):
        return shlex.join(str(arg) for arg in args)

    mutations = "/var/lib/agent-sandbox-test/dynamic-mutations"
    fsmon_pattern = "^/nix/store/[^ ]*/bin/agent-sandbox-fsmon"
    shared_dir = "/run/agent-sandbox/shared"
    sandbox_socket = shared_dir + "/sandbox-policy.sock"

    start_all()
    dynamic.wait_for_unit("multi-user.target")
    dynamic.wait_for_unit("agent-sandbox-policy.socket")
    dynamic.wait_for_unit("agent-sandbox-policy.service")
    # The live sandbox must start in its own scope, so the lingering user
    # manager has to be up first.
    dynamic.wait_for_unit("user@1000.service")

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
        "inode) test \"$(stat -c %i \"$first\")\" = \"$second\";; "
        "connect) exec 4<>\"/dev/tcp/$first/$second\";; "
        "echo) printf '%s\\n' \"$first\" >&4 && read -r -t 5 reply <&4 && test \"$reply\" = \"$first\";; "
        "net) (exec 3<>\"/dev/tcp/$first/$second\");; "
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

    # systemd kept the socket open across the restart, and the sandbox's own
    # monitor is still running.
    assert dynamic.succeed(command("stat", "-c", "%i", sandbox_socket)).strip() == socket_inode
    dynamic.succeed(command("kill", "-0", fsmon_pid))
    assert dynamic.succeed(command("pgrep", "-f", fsmon_pattern)).split() == [fsmon_pid]

    # The same sandbox keeps mutating and stays confined.
    mutate_and_check("after-restart")
    probe("read", "/var/lib/agent-sandbox-test/dynamic-read")
    probe("read", "/var/lib/agent-sandbox-test/dynamic-unlisted", allowed=False)
    dynamic.succeed(command("kill", "-0", fsmon_pid))

    # A system switch that changes the policyd unit restarts it in place and
    # leaves the socket open, so requests never find it missing. The same
    # switch changes the namespace, loopback bridge and DNS forwarder units:
    # the namespace and bridge stay up, the forwarder restarts alone, and a
    # connection the sandbox holds open keeps working.
    def unit(prop, name):
        return dynamic.succeed(command("systemctl", "show", "-p", prop, "--value", name)).strip()

    netns_path = "/run/netns/agent-sandbox"
    dynamic.wait_for_unit("agent-sandbox-loopback.service")
    dynamic.wait_for_unit("agent-sandbox-vm-loopback-host.service")
    dynamic.wait_for_unit("agent-sandbox-vm-echo.service")
    probe("net", "127.0.0.1", "18089")
    probe("connect", "169.254.100.1", "18095")
    probe("echo", "before-switch")

    before = {
        "netns": dynamic.succeed(command("stat", "-L", "-c", "%i", netns_path)).strip(),
        "netns_invocation": unit("InvocationID", "agent-sandbox-netns.service"),
        "loopback_invocation": unit("InvocationID", "agent-sandbox-loopback.service"),
        "nfq": unit("MainPID", "agent-sandbox-nfq.service"),
        "dns": unit("MainPID", "agent-sandbox-dns.service"),
        "policyd": unit("MainPID", "agent-sandbox-policy.service"),
    }
    dynamic.succeed("/run/booted-system/specialisation/changed-policyd/bin/switch-to-configuration test")
    dynamic.wait_for_unit("agent-sandbox-policy.service")
    dynamic.wait_for_unit("agent-sandbox-dns.service")
    assert unit("MainPID", "agent-sandbox-policy.service") != before["policyd"]
    assert unit("MainPID", "agent-sandbox-dns.service") != before["dns"]
    assert unit("MainPID", "agent-sandbox-nfq.service") == before["nfq"], "nfq restarted"
    assert unit("InvocationID", "agent-sandbox-netns.service") == before["netns_invocation"], "netns restarted"
    assert unit("InvocationID", "agent-sandbox-loopback.service") == before["loopback_invocation"], "loopback restarted"
    assert dynamic.succeed(command("stat", "-L", "-c", "%i", netns_path)).strip() == before["netns"]
    assert dynamic.succeed(command("stat", "-c", "%i", sandbox_socket)).strip() == socket_inode

    probe("echo", "after-switch")
    probe("net", "127.0.0.1", "18089")
    probe("net", "169.254.100.1", "18095")
    mutate_and_check("after-switch")
    probe("read", "/var/lib/agent-sandbox-test/dynamic-unlisted", allowed=False)
    dynamic.succeed(command("kill", "-0", fsmon_pid))

    # Restarting the socket unit replaces the socket inode. The sandbox binds
    # the shared directory, so it reaches the new socket by path.
    dynamic.succeed("systemctl restart agent-sandbox-policy.socket agent-sandbox-policy.service")
    dynamic.wait_for_unit("agent-sandbox-policy.socket")
    dynamic.wait_for_unit("agent-sandbox-policy.service")
    assert dynamic.succeed(command("stat", "-c", "%i", sandbox_socket)).strip() != socket_inode
    mutate_and_check("after-socket-restart")
    probe("read", "/var/lib/agent-sandbox-test/dynamic-unlisted", allowed=False)

    # A file the host replaces by rename in the shared directory is the new
    # file inside the running sandbox too.
    shared_file = shared_dir + "/replaced"
    dynamic.succeed(command("sh", "-c", "printf old > " + shared_file))
    probe("inode", shared_file, dynamic.succeed(command("stat", "-c", "%i", shared_file)).strip())
    dynamic.succeed(command("sh", "-c", "printf new > " + shared_file + ".tmp && mv " + shared_file + ".tmp " + shared_file))
    probe("inode", shared_file, dynamic.succeed(command("stat", "-c", "%i", shared_file)).strip())
    dynamic.succeed(command("rm", shared_file))

    # A sandbox launched after the restart works against the new policyd.
    dynamic.succeed(command(
        "runuser", "-u", "sandbox", "--", "sandbox-dynamic-bash", "-c",
        "printf fresh > " + mutations + "/fresh && mv " + mutations + "/fresh " + mutations + "/fresh-renamed && rm " + mutations + "/fresh-renamed",
    ))
    dynamic.succeed(command("test", "!", "-e", mutations + "/fresh-renamed"))

    # The node runs the network-mode launcher: no PID namespace, so only
    # policyd's scope kill stops what a finished sandbox leaves behind.
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
        bwrap = dynamic.succeed("pgrep -P " + launcher + " -x bwrap").split()[0]
        argv = dynamic.succeed("tr '\\0' '\\n' < /proc/" + bwrap + "/cmdline").split()
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
    # reports the agent's own exit status, not the kill's.
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

    # The long-lived sandbox registered with a policyd that has been
    # restarted since. policyd restored the registration and armed its
    # launcher watch again, so killing the launcher still takes the whole
    # scope, and the sandbox's own fsmon, with it.
    # runuser and its shell parent carry the same command line but run in the
    # restart-live service unit; only the sandboxed processes are in the scope.
    live_scope = None
    for pid in dynamic.succeed("pgrep -u sandbox -f 'while read -r token'").split():
        cgroup = dynamic.succeed("sed -n 's/^0:://p' /proc/" + pid + "/cgroup").strip()
        match = re.fullmatch(r".*/agent-sandbox-(\d+)_\d+\.scope", cgroup)
        if match:
            live, live_cgroup, live_scope = pid, cgroup, match
            break
    assert live_scope, "the live sandbox is not in its own scope"
    dynamic.succeed("kill -KILL " + live_scope.group(1))
    dynamic.wait_until_fails("test -e /proc/" + live, timeout=10)
    dynamic.wait_until_fails("test -e /proc/" + fsmon_pid, timeout=10)
    dynamic.wait_until_fails("test -e /sys/fs/cgroup" + live_cgroup, timeout=10)
  '';
})
