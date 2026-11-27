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
    mkBash
    module
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
  # Mounts through the fusermount3 shim the way go-fuse does. The mountpoint
  # has no filesystem rule, so policyd holds the mount on an approval prompt
  # that freezes the whole sandbox, the waiting shim included.
  probe = pkgs.writeText "fuse-approval-probe.py" ''
    import os
    import socket
    import subprocess
    import sys

    mountpoint = sys.argv[1]
    local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    proc = subprocess.run(
        ["fusermount3", mountpoint, "-o", "default_permissions,nodev,nosuid,noatime,fsname=prompt,subtype=prompt"],
        env=dict(os.environ, _FUSE_COMMFD=str(remote.fileno())),
        pass_fds=[remote.fileno()],
        capture_output=True,
        text=True,
    )
    remote.close()
    assert proc.returncode == 0, f"mount failed: {proc.returncode} {proc.stderr!r}"
    fds = socket.recv_fds(local, 4, 4)[1]
    assert len(fds) == 1, fds
    with open("/proc/self/mountinfo") as mountinfo:
        assert any(f" {mountpoint} " in line and " - fuse.prompt " in line for line in mountinfo), "no mount"
    os.close(fds[0])
    subprocess.run(["fusermount3", "-u", mountpoint], check=True)
  '';
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-filesystem-fuse-approval";
  node.specialArgs = { inherit inputs; };

  nodes.fuse =
    _:
    lib.recursiveUpdate baseNode {
      imports = [ module ];

      boot.kernelModules = [ "fuse" ];

      agent-sandbox = {
        enable = true;
        gates.filesystem.enable = true;

        packages = [
          (mkBash "sandbox-fuse-bash" {
            extraPkgs = commonExtraPkgs ++ [ pkgs.python3 ];
          })
        ];

        # Pending requests are recorded but no UI is spawned; the scenario
        # resolves them with agent-sandbox-approve.
        policy.uiBackend = "none";
      };
    };

  testScript = ''
    import shlex
    import time

    approve = "runuser -u sandbox -- agent-sandbox-approve"
    mountpoint = "/var/lib/agent-sandbox-test/fuse-prompt"

    start_all()
    fuse.wait_for_unit("multi-user.target")
    fuse.wait_for_unit("agent-sandbox-policy.service")
    fuse.succeed(f"install -d -m 0755 -o sandbox -g users {mountpoint}")
    fuse.succeed(
        "systemd-run --unit=fuse-prompt --service-type=exec "
        + "--setenv=PATH=/run/wrappers/bin:/run/current-system/sw/bin "
        + "runuser -u sandbox -- sandbox-fuse-bash -c "
        + shlex.quote(f"python3 -I ${probe} {mountpoint}")
    )

    # The mount waits on a filesystem prompt for its mountpoint, which froze
    # the sandbox while the shim waits for policyd's reply. Reads outside the
    # policy before it, such as /etc/passwd, prompt too and are approved once.
    prompt = None
    for _ in range(120):
        for line in fuse.succeed(f"{approve} pending").splitlines():
            fields = line.split("\t")
            if len(fields) < 5 or fields[1] != "filesystem":
                continue
            if fields[4] == mountpoint:
                prompt = fields[0]
                break
            fuse.succeed(f"{approve} approve {fields[0]} once")
        if prompt:
            break
        time.sleep(0.5)
    assert prompt, fuse.succeed("journalctl -u fuse-prompt.service --no-pager")
    fuse.succeed(
        "pid=$(pgrep -u sandbox -f '^[^ ]*python3 -I [^ ]*fuse-approval-probe\\.py' | head -1); "
        + "scope=$(awk -F: '$1 == 0 {print $3}' /proc/$pid/cgroup); "
        + "test \"$(cat /sys/fs/cgroup$scope/cgroup.freeze)\" = 1"
    )
    fuse.succeed(f"{approve} approve {prompt} once")

    # The thaw interrupts the shim's wait; it keeps waiting and hands the
    # client the /dev/fuse descriptor. The probe exits non-zero on any failure.
    fuse.wait_until_fails("systemctl is-active --quiet fuse-prompt.service", timeout=60)
    if fuse.execute("systemctl is-failed --quiet fuse-prompt.service")[0] == 0:
        print(fuse.succeed("journalctl -u fuse-prompt.service --no-pager"))
        raise Exception("the FUSE mount failed after its approval")
  '';
})
