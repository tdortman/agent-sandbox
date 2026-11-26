"""Drive the sandbox's fusermount3 shim the way go-fuse does and check what it refuses."""

import os
import socket
import subprocess

DIR = "/var/lib/agent-sandbox-test/dynamic-mutations"


def fusermount(*args):
    """Run fusermount3 with _FUSE_COMMFD set; return its status, stderr and received fds."""
    local, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    env = dict(os.environ, _FUSE_COMMFD=str(remote.fileno()))
    proc = subprocess.run(
        ["fusermount3", *args],
        env=env,
        pass_fds=[remote.fileno()],
        capture_output=True,
        text=True,
    )
    remote.close()
    local.setblocking(False)
    try:
        fds = socket.recv_fds(local, 4, 4)[1]
    except BlockingIOError:
        fds = []
    local.close()
    return proc.returncode, proc.stderr, fds


def fuse_mounts():
    with open("/proc/self/mountinfo") as mountinfo:
        return [line for line in mountinfo if " - fuse" in line]


def refused(label, args, needle):
    before = fuse_mounts()
    status, error, fds = fusermount(*args)
    assert status != 0 and not fds, f"{label}: went through: {status} {error!r}"
    assert needle in error, f"{label}: {error!r}"
    assert fuse_mounts() == before, f"{label}: mount table changed"
    print(f"refused {label}: {error.strip()}")


mountpoint = f"{DIR}/fuse-probe-mnt"
os.makedirs(mountpoint, exist_ok=True)
if not os.path.islink(f"{DIR}/fuse-probe-link"):
    os.symlink("fuse-probe-mnt", f"{DIR}/fuse-probe-link")

refused("allow_other", [mountpoint, "-o", "allow_other"], "allow_other")
refused("suid", [mountpoint, "-o", "suid"], "not permitted")
refused("unknown option", [mountpoint, "-o", "bogus"], "unknown option")
refused("symlinked mountpoint", [f"{DIR}/fuse-probe-link", "-o", "rw"], "symlink")
refused("foreign owner", [f"{DIR}/root-owned", "-o", "rw"], "not owned")
refused("shared directory", ["/run/agent-sandbox/shared", "-o", "rw"], "refusing to mount")
refused("outside filesystem policy", ["/var/lib/agent-sandbox-test/fuse-unlisted", "-o", "rw"], "filesystem policy")
refused("unmount of a non-FUSE mount", ["-u", "/tmp"], "not a FUSE mount")
refused("unmount of a plain directory", ["-u", mountpoint], "not a FUSE mount")

# The shim answers at the path libfuse hardcodes and on PATH.
for binary in ("/run/wrappers/bin/fusermount3", "fusermount3", "/run/wrappers/bin/fusermount"):
    version = subprocess.run([binary, "-V"], capture_output=True, text=True, check=True).stdout
    assert "agent-sandbox" in version, f"{binary}: {version!r}"

# A mount hands the /dev/fuse descriptor back over _FUSE_COMMFD.
before = fuse_mounts()
status, error, fds = fusermount(
    mountpoint, "-o", "default_permissions,nodev,nosuid,noatime,fsname=probe,subtype=probe,max_read=131072"
)
assert status == 0 and len(fds) == 1, f"mount failed: {status} {error!r} {fds}"
assert os.stat("/dev/fuse").st_rdev == os.fstat(fds[0]).st_rdev, "descriptor is not /dev/fuse"
added = [line for line in fuse_mounts() if line not in before]
assert len(added) == 1, added
fields = added[0].split(" - ")[0].split(" ")[5].split(",")
assert {"nosuid", "nodev", "noatime"} <= set(fields), fields
assert f"user_id={os.getuid()}" in added[0], added[0]
assert " fuse.probe probe " in added[0], added[0]
print("mounted:", added[0].strip())

# Dropping the only descriptor kills the connection; -u clears the dead mount.
os.close(fds[0])
status, error, _ = fusermount("-u", mountpoint)
assert status == 0, f"unmount failed: {error!r}"
assert fuse_mounts() == before, "mount survived -u"
