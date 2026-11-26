# Regression guard for `agent-sandbox.policy.pauseClockWhileFrozen`.
#
# An approval prompt freezes the sandbox's cgroup while its CLOCK_MONOTONIC
# and CLOCK_BOOTTIME keep running, so timeouts fire on thaw. With the option
# on, each sandbox runs in its own time namespace and policyd rewinds the
# namespace's offsets by the frozen time before thawing. One sandbox launch
# holds an HTTP/3 connection (10 s idle timeout, no keep-alive) idle across a
# 40 s prompt and reads its clocks before and after; the connection must
# survive and the clocks must advance by seconds, not by the prompt's length.
{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e) proxyNode sandboxPkg;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-approval-clock";
  node.specialArgs = { inherit inputs; };

  nodes.clock = lib.recursiveUpdate proxyNode {
    agent-sandbox = {
      gates.syscalls.enable = false;

      policy = {
        interactiveApproval = true;
        pauseClockWhileFrozen = true;
      };
    };
  };

  testScript = ''
    import shlex
    import textwrap

    client = "${sandboxPkg}/bin/h3-idle-client"
    prompt_seconds = 40
    out = "/tmp/clock-pause.out"
    uptime = "cut -d' ' -f1 /proc/uptime"
    approve = "runuser -u sandbox -- agent-sandbox-approve"

    # Host-side ioctl probe of the module's refusal rules. Exits non-zero
    # with a message on the first unexpected errno.
    rewind_probe = """
    import errno, fcntl, os, struct, sys

    REWIND = 0x4010B701
    pid = sys.argv[1]
    dev = os.open('/dev/agent-sandbox-timens', os.O_RDWR)

    def rewind(ns_path, flags, seconds):
        ns_fd = os.open(ns_path, os.O_RDONLY)
        try:
            fcntl.ioctl(dev, REWIND, struct.pack('=iIQ', ns_fd, flags, seconds))
            return 0
        except OSError as error:
            return error.errno
        finally:
            os.close(ns_fd)

    def offsets():
        with open(f'/proc/{pid}/timens_offsets') as handle:
            return handle.read()

    def expect(label, actual, wanted):
        assert actual == wanted, f'{label}: got {errno.errorcode.get(actual, actual)}, want {errno.errorcode[wanted]}'

    sandbox_ns = f'/proc/{pid}/ns/time'
    before = offsets()
    expect('running sandbox', rewind(sandbox_ns, 0, 1), errno.EBUSY)
    expect('host namespace', rewind('/proc/self/ns/time', 0, 1), errno.EINVAL)
    expect('nonzero flags', rewind(sandbox_ns, 1, 1), errno.EINVAL)
    expect('zero seconds', rewind(sandbox_ns, 0, 0), errno.EINVAL)
    assert offsets() == before, 'offsets changed by refused rewinds'
    print('rewind probe ok')
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

    start_all()
    clock.wait_for_unit("multi-user.target")
    clock.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
    clock.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
    clock.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
    clock.wait_for_unit("agent-sandbox-policy.service")
    clock.wait_for_unit("agent-sandbox-vm-h3-http.service", timeout=120)
    clock.wait_for_open_port(8008)

    clock.succeed("lsmod | grep -q '^agent_sandbox_timens '")
    clock.succeed("test \"$(stat -c '%a %U:%G' /dev/agent-sandbox-timens)\" = '600 root:root'")
    clock.succeed(
        f"runuser -u sandbox -- ${pkgs.python3}/bin/python3 -c {shlex.quote(textwrap.dedent(unprivileged_probe))}"
    )

    # A running (not frozen) sandbox's namespace refuses a rewind.
    clock.succeed(
        "nohup runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 "
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
        "sandbox-proxy-bash -c 'exec sleep 3001' </dev/null >/dev/null 2>&1 &"
    )
    sleeper_pid = clock.wait_until_succeeds(
        "pid=$(pgrep -f '^[^ ]*sleep 3001$' | head -1); test -n \"$pid\" && echo $pid"
    ).strip()
    clock.succeed(
        f"${pkgs.python3}/bin/python3 -c {shlex.quote(textwrap.dedent(rewind_probe))} {sleeper_pid}"
    )
    clock.succeed(f"kill {sleeper_pid}")

    host_ns = clock.succeed("readlink /proc/self/ns/time").strip()
    host_start = float(clock.succeed(uptime))

    # Name resolution in the sandbox before the scenario keeps DNS prompts
    # out of the timed window.
    clock.succeed(
        "runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 "
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
        "sandbox-proxy-bash -c "
        + shlex.quote("python3 -c 'import socket; socket.getaddrinfo(\"h3-allowed.test\", 443)'")
    )

    # The wrapper records $PWD as the project root, so launch from the
    # sandbox user's home.
    launch = "cd /home/user && " + shlex.join(["sandbox-proxy-bash", "-c", scenario])
    clock.succeed(
        "nohup runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 "
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
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
})
