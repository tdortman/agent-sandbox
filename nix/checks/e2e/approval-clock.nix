# Shared parts of the `agent-sandbox.policy.pauseClockWhileFrozen` checks.
#
# An approval prompt freezes the sandbox's cgroup while its CLOCK_MONOTONIC
# and CLOCK_BOOTTIME keep running, so timeouts fire on thaw. With the option
# on, each sandbox runs in its own time namespace and policyd rewinds the
# namespace's offsets by the frozen time before thawing, through the
# `agent_sandbox_timens` kernel module. The parts are small checks that run
# in parallel:
#
# - `ioctl`: the module's device, its refusal rules and who may reach it.
# - `cgroupfs`: a sandbox cannot write any cgroup's `cgroup.freeze`.
# - `pause`: a 40 s prompt with an idle HTTP/3 connection leaves the
#   sandbox's clocks and the connection intact.
{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e) proxyNode sandboxPkg;
  e2e = import ./common.nix {
    inherit inputs lib pkgs;
  };

  dynamicSandboxPolicy = e2e.mkPolicy "clock-cgroupfs" {
    filesystem = ''
      {
        "allow": [
          { "path": "/etc/passwd", "access": "read" },
          { "path": "/etc/group", "access": "read" }
        ],
        "deny": []
      }
    '';
  };

  python = "${pkgs.python3}/bin/python3";
  unshare = "${pkgs.util-linux}/bin/unshare";

  mkCheck =
    {
      name,
      testScript,
      node ? { },
    }:
    pkgs.testers.runNixOSTest (_: {
      inherit name;
      node.specialArgs = { inherit inputs; };

      nodes.clock = lib.recursiveUpdate (lib.recursiveUpdate proxyNode {
        agent-sandbox = {
          gates.syscalls.enable = false;

          policy = {
            interactiveApproval = true;
            pauseClockWhileFrozen = true;
          };
        };
      }) node;

      testScript = ''
        import shlex
        import textwrap

        approve = "runuser -u sandbox -- agent-sandbox-approve"
        uptime = "cut -d' ' -f1 /proc/uptime"
        sandbox_env = (
            "XDG_RUNTIME_DIR=/run/user/1000 "
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
        )


        def as_sandbox(command):
            """A host command line that runs `command` in a sandbox as the sandbox user."""
            return (
                f"runuser -u sandbox -- env {sandbox_env} "
                "sandbox-proxy-bash -c " + shlex.quote(command)
            )


        def python_source(source):
            return shlex.quote(textwrap.dedent(source))


        def start_sleeper(seconds):
            """Start `sleep <seconds>` in a sandbox and return its host pid."""
            clock.succeed(
                f"nohup {as_sandbox(f'exec sleep {seconds}')} </dev/null >/dev/null 2>&1 &"
            )
            return clock.wait_until_succeeds(
                f"pid=$(pgrep -f '^[^ ]*sleep {seconds}$' | head -1); test -n \"$pid\" && echo $pid"
            ).strip()


        start_all()
        clock.wait_for_unit("multi-user.target")
        clock.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
        clock.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
        clock.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
        clock.wait_for_unit("agent-sandbox-policy.service")
        clock.wait_for_unit("agent-sandbox-vm-h3-http.service", timeout=120)
        clock.wait_for_open_port(8008)
        clock.succeed("lsmod | grep -q '^agent_sandbox_timens '")

      ''
      + testScript;
    });

  ioctlScript = ''
    # Host-side ioctl probes of the module's refusal rules. Each exits
    # non-zero with a message on the first unexpected errno.
    #
    # ABI: struct { s32 ns_fd; s32 cgroup_fd; u32 flags; u32 reserved; u64
    # seconds; }, 24 bytes. EBADF: bad ns_fd or a cgroup_fd that is no cgroup2
    # directory. EINVAL: flags or reserved set, seconds out of range, a
    # namespace that is the host's or not owned by the initial user namespace.
    # EAGAIN: no freeze requested on the cgroup. EXDEV: a task of the
    # namespace lives outside the cgroup. EBUSY: a task is not trapped yet.
    probe_prelude = """
    import errno, fcntl, os, struct, sys, time

    REWIND = 0x4018B701
    dev = os.open('/dev/agent-sandbox-timens', os.O_RDWR)

    def rewind(ns_path, cgroup_path, flags=0, seconds=1, reserved=0):
        ns_fd = os.open(ns_path, os.O_RDONLY)
        cgroup_fd = os.open(cgroup_path, os.O_RDONLY) if isinstance(cgroup_path, str) else cgroup_path
        try:
            fcntl.ioctl(dev, REWIND, struct.pack('=iiIIQ', ns_fd, cgroup_fd, flags, reserved, seconds))
            return 0
        except OSError as error:
            return error.errno
        finally:
            os.close(ns_fd)
            if isinstance(cgroup_path, str):
                os.close(cgroup_fd)

    def offsets(pid):
        with open(f'/proc/{pid}/timens_offsets') as handle:
            return handle.read()

    def expect(label, actual, wanted):
        assert actual == wanted, f'{label}: got {errno.errorcode.get(actual, actual)}, want {errno.errorcode[wanted]}'
    """

    # A running sandbox: no scope has a freeze requested.
    rewind_probe = probe_prelude + """
    pid = sys.argv[1]
    scope = '/sys/fs/cgroup' + [
        line.split('::', 1)[1].strip() for line in open(f'/proc/{pid}/cgroup') if line.startswith('0::')
    ][0]
    sandbox_ns = f'/proc/{pid}/ns/time'
    before = offsets(pid)
    expect('running sandbox', rewind(sandbox_ns, scope), errno.EAGAIN)
    expect('host root cgroup', rewind(sandbox_ns, '/sys/fs/cgroup'), errno.EAGAIN)
    expect('host namespace', rewind('/proc/self/ns/time', scope), errno.EINVAL)
    expect('nonzero flags', rewind(sandbox_ns, scope, flags=1), errno.EINVAL)
    expect('nonzero reserved', rewind(sandbox_ns, scope, reserved=1), errno.EINVAL)
    expect('zero seconds', rewind(sandbox_ns, scope, seconds=0), errno.EINVAL)
    expect('too many seconds', rewind(sandbox_ns, scope, seconds=(1 << 32) + 1), errno.EINVAL)
    expect('device as cgroup', rewind(sandbox_ns, dev), errno.EBADF)
    expect('closed cgroup fd', rewind(sandbox_ns, 1000), errno.EBADF)
    expect('file as cgroup', rewind(sandbox_ns, '/proc/self/ns/time'), errno.EBADF)
    assert offsets(pid) == before, 'offsets changed by refused rewinds'
    print('rewind probe ok')
    """

    # Two staged cgroups on the host. A holds a member of a fresh time
    # namespace in a child cgroup A/sub (argv[1]); B is an unrelated frozen
    # scope. argv[2] is a time namespace owned by a user namespace.
    staged_probe = probe_prelude + """
    member, userns_member = sys.argv[1], sys.argv[2]
    root = '/sys/fs/cgroup'
    a, b = f'{root}/clockprobe-a', f'{root}/clockprobe-b'
    ns = f'/proc/{member}/ns/time'

    def freeze(path, on):
        with open(f'{path}/cgroup.freeze', 'w') as handle:
            handle.write('1' if on else '0')

    def wait_state(path, frozen):
        for _ in range(100):
            with open(f'{path}/cgroup.events') as handle:
                if f'frozen {int(frozen)}' in handle.read():
                    return
            time.sleep(0.1)
        raise SystemExit(f'{path} did not reach frozen={frozen}')

    before = offsets(member)
    expect('no freeze on the right cgroup', rewind(ns, a), errno.EAGAIN)

    for path in (a, b):
        freeze(path, True)
    for path in (a, f'{a}/sub', b):
        wait_state(path, True)

    # The namespace's tasks are all frozen, but not all in B.
    expect('frozen foreign scope', rewind(ns, b), errno.EXDEV)
    expect('host root cgroup', rewind(ns, root), errno.EAGAIN)
    expect('namespace owned by a user namespace', rewind(f'/proc/{userns_member}/ns/time', a), errno.EINVAL)

    # B thaws: no freeze requested there, whatever its members.
    freeze(b, False)
    wait_state(b, False)
    expect('thawed foreign scope', rewind(ns, b), errno.EAGAIN)
    assert offsets(member) == before, 'offsets changed by refused rewinds'

    # Every member is in A's subtree and frozen: the rewind goes through.
    expect('frozen owning scope', rewind(ns, a), 0)
    monotonic = [line.split() for line in offsets(member).splitlines() if line.startswith('monotonic')][0]
    assert monotonic[1] == '-1', offsets(member)

    freeze(a, False)
    print('staged probe ok')
    """

    # Run inside a sandbox: neither the control device nor the enter wrapper
    # is usable there.
    sandbox_probe = """
    import errno, os
    assert not os.path.exists('/run/wrappers/bin/agent-sandbox-enter'), 'enter wrapper visible'
    try:
        os.open('/dev/agent-sandbox-timens', os.O_RDWR)
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM, errno.ENOENT), error
        print('sandbox open refused', error.errno)
    else:
        raise SystemExit('sandbox opened the control device')
    """

    unprivileged_probe = """
    import errno, os
    try:
        os.open('/dev/agent-sandbox-timens', os.O_RDWR)
    except OSError as error:
        assert error.errno == errno.EACCES, error
        print('open refused')
    else:
        raise SystemExit('unprivileged open succeeded')
    """

    clock.succeed("test \"$(stat -c '%a %U:%G' /dev/agent-sandbox-timens)\" = '600 root:root'")
    clock.succeed(
        f"runuser -u sandbox -- ${python} -c {python_source(unprivileged_probe)}"
    )
    clock.succeed(as_sandbox(f"python3 -c {python_source(sandbox_probe)}"))

    # A time namespace owned by a user namespace cannot be rewound; a
    # sandbox can create one when user namespaces are available to it.
    clock.succeed(
        "nohup runuser -u sandbox -- ${unshare} --user --map-root-user "
        "--time --fork sleep 3003 </dev/null >/dev/null 2>&1 &"
    )
    userns_pid = clock.wait_until_succeeds(
        "pid=$(pgrep -f '^[^ ]*sleep 3003$' | head -1); test -n \"$pid\" && echo $pid"
    ).strip()

    # A fresh time namespace, with its only task in a child of cgroup A.
    clock.succeed("mkdir -p /sys/fs/cgroup/clockprobe-a/sub /sys/fs/cgroup/clockprobe-b")
    clock.succeed(
        "nohup sh -c 'echo $$ > /sys/fs/cgroup/clockprobe-a/sub/cgroup.procs; "
        "exec ${unshare} --time --fork sleep 3002' </dev/null >/dev/null 2>&1 &"
    )
    member_pid = clock.wait_until_succeeds(
        "pid=$(pgrep -f '^[^ ]*sleep 3002$' | head -1); test -n \"$pid\" && echo $pid"
    ).strip()
    clock.succeed(
        f"${python} -c {python_source(staged_probe)} {member_pid} {userns_pid}"
    )
    clock.succeed(f"kill {member_pid} {userns_pid}")
    clock.succeed(
        "for _ in $(seq 50); do rmdir /sys/fs/cgroup/clockprobe-a/sub 2>/dev/null && break; sleep 0.2; done; "
        "rmdir /sys/fs/cgroup/clockprobe-a /sys/fs/cgroup/clockprobe-b"
    )

    # A running (not frozen) sandbox's namespace refuses a rewind.
    sleeper_pid = start_sleeper(3001)
    clock.succeed(
        f"${python} -c {python_source(rewind_probe)} {sleeper_pid}"
    )
    clock.succeed(f"kill {sleeper_pid}")
  '';

  cgroupfsScript = ''
    # Run inside a second (dynamic) sandbox while another runs: no cgroup
    # control file of the other sandbox's scope, of its own scope or of the
    # user's app.slice above both may be written. Writing 0 (thaw) keeps a
    # regression from freezing anything while it is being detected.
    cgroup_probe = """
    import errno, sys
    victim = sys.argv[1]
    own = '/sys/fs/cgroup' + [
        line.split('::', 1)[1].strip() for line in open('/proc/self/cgroup') if line.startswith('0::')
    ][0]
    for path in (f'{victim}/cgroup.freeze', f'{victim}/../cgroup.freeze', f'{own}/cgroup.freeze'):
        try:
            with open(path, 'w') as handle:
                handle.write('0')
        except OSError as error:
            assert error.errno in (errno.EROFS, errno.EPERM, errno.EACCES, errno.ENOENT), (path, error)
            print('refused', path, errno.errorcode[error.errno])
        else:
            raise SystemExit(f'sandbox wrote {path}')
    """

    sleeper_pid = start_sleeper(3001)
    sleeper_scope = clock.succeed(
        f"echo /sys/fs/cgroup$(awk -F: '$1 == 0 {{print $3}}' /proc/{sleeper_pid}/cgroup)"
    ).strip()
    probe_out = clock.succeed(
        as_sandbox(f"python3 -c {python_source(cgroup_probe)} {sleeper_scope}")
    )
    assert probe_out.count("refused") == 3, probe_out
    assert "EROFS" in probe_out, probe_out
    clock.succeed(
        f"test \"$(cat {sleeper_scope}/cgroup.freeze)\" = 0"
    )
    clock.succeed(f"kill {sleeper_pid}")
  '';

  pauseScript = ''
    client = "${sandboxPkg}/bin/h3-idle-client"
    prompt_seconds = 40
    out = "/tmp/clock-pause.out"

    # One sandbox launch, so one freeze covers the client, the clock
    # readers and the prompting curl. The client's trigger file lives in the
    # sandbox's own scratch directory.
    scenario = f"""
    work=$(mktemp -d)
    mono() {{ python3 -c 'import time; print(time.monotonic())'; }}
    up() {{ {uptime}; }}
    echo "ns $(readlink /proc/self/ns/time)"
    echo "mono0 $(mono)"
    echo "up0 $(up)"
    {client} --ca-file /run/agent-sandbox/shared/proxy-ca-bundle.pem --trigger-file $work/go https://h3-allowed.test:443/allowed >$work/client.out 2>&1 &
    client=$!
    until grep -q 'request 1 ok' $work/client.out; do kill -0 $client || break; sleep 0.2; done
    curl --silent --show-error --max-time 120 http://169.254.100.1:8008/unlisted
    echo "curl $?"
    echo "mono1 $(mono)"
    echo "up1 $(up)"
    sleep 4
    touch $work/go
    wait $client
    echo "client $?"
    cat $work/client.out
    echo "mono2 $(mono)"
    echo "up2 $(up)"
    echo done
    """

    host_ns = clock.succeed("readlink /proc/self/ns/time").strip()
    host_start = float(clock.succeed(uptime))

    # Name resolution in the sandbox before the scenario keeps DNS prompts
    # out of the timed window.
    clock.succeed(
        as_sandbox("python3 -c 'import socket; socket.getaddrinfo(\"h3-allowed.test\", 443)'")
    )

    # The wrapper records $PWD as the project root, so launch from the
    # sandbox user's home.
    launch = "cd /home/user && " + shlex.join(["sandbox-proxy-bash", "-c", scenario])
    clock.succeed(
        f"nohup runuser -u sandbox -- env {sandbox_env} "
        f"sh -c {shlex.quote(launch)} </dev/null >{out} 2>&1 &"
    )

    clock.wait_until_succeeds(
        f"{approve} pending | grep -F -q 'http://169.254.100.1:8008/unlisted'"
    )
    clock.wait_until_succeeds(
        "pid=$(pgrep -f '^[^ ]*curl .*8008/unlisted' | head -1); "
        "scope=$(awk -F: '$1 == 0 {print $3}' /proc/$pid/cgroup); "
        "test \"$(cat /sys/fs/cgroup$scope/cgroup.freeze)\" = 1"
    )
    client_pid = clock.succeed("pgrep -f '^[^ ]*h3-idle-client ' | head -1").strip()
    assert client_pid, "h3-idle-client is not running"

    # Longer than the client's 10 s idle timeout and the proxy's 30 s one.
    clock.succeed(f"sleep {prompt_seconds}")
    prompt_id = clock.succeed(
        f"{approve} pending | awk -F'\\t' '$2 == \"http\" && $5 ~ /unlisted/ {{print $1; exit}}'"
    ).strip()
    assert prompt_id, "no pending approval for /unlisted"
    clock.succeed(f"{approve} approve {prompt_id} once")

    # The client lingers 4 s after the thaw, so its namespace is still
    # readable from the host here.
    offsets = clock.wait_until_succeeds(
        f"grep -q '^mono1 ' {out} && cat /proc/{client_pid}/timens_offsets"
    )
    clock.wait_until_succeeds(f"grep -q '^done$' {out}", timeout=120)
    host_elapsed = float(clock.succeed(uptime)) - host_start
    result = clock.succeed(f"cat {out}")
    print(result)
    print(offsets)

    values = {}
    for line in result.splitlines():
        key, _, value = line.partition(" ")
        values.setdefault(key, value)

    sandbox_ns = values["ns"]
    mono = [float(values[f"mono{i}"]) for i in range(3)]
    up = [float(values[f"up{i}"]) for i in range(3)]
    monotonic_offset = next(
        int(line.split()[1]) for line in offsets.splitlines() if line.startswith("monotonic")
    )

    assert sandbox_ns != host_ns, (sandbox_ns, host_ns)
    assert host_elapsed >= prompt_seconds, host_elapsed
    assert mono[1] - mono[0] < 5, f"monotonic advanced {mono[1] - mono[0]} s across the freeze"
    assert up[1] - up[0] < 5, f"uptime advanced {up[1] - up[0]} s across the freeze"
    assert mono[2] - mono[0] < 15 and up[2] - up[0] < 15, (mono, up)
    assert mono == sorted(mono) and up == sorted(up), f"clock went backwards: {mono} {up}"
    assert monotonic_offset <= -(prompt_seconds - 5), offsets
    assert values["client"] == "0", result
    assert "request 2 reused connection" in result, result
  '';
in
{
  ioctl = mkCheck {
    name = "e2e-approval-clock-ioctl";
    testScript = ioctlScript;
  };

  cgroupfs = mkCheck {
    name = "e2e-approval-clock-cgroupfs";
    # The dynamic filesystem launcher binds the host's cgroupfs read-only;
    # the static one shows no cgroupfs at all. Unlisted accesses are denied
    # at once instead of waiting for a prompt nobody answers.
    node = lib.recursiveUpdate (e2e.installPolicy dynamicSandboxPolicy) {
      agent-sandbox = {
        gates.filesystem.enable = true;
        policy.interactiveApproval = false;
        policy.uiBackend = "none";
      };
    };
    testScript = cgroupfsScript;
  };

  pause = mkCheck {
    name = "e2e-approval-clock-pause";
    testScript = pauseScript;
  };
}
