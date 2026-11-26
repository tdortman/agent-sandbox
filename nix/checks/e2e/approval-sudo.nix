{
  lib,
  pkgs,
  inputs,
}:
let
  inherit (e2e)
    baseNode
    installPolicy
    module
    sudoApprovePackages
    sudoDenyPackages
    sudoPolicy
    ;
  e2e = import ./common.nix { inherit inputs lib pkgs; };
  # The sandbox side of the fuse scenario. Each phase holds its mount open
  # until the host has looked for it.
  fuseScript = ''
    set -eu
    D=$HOME/sandbox-readwrite
    hold() {
      touch "$D/fuse-$1-held"
      while [ ! -e "$D/fuse-$1-release" ]; do sleep 0.1; done
    }
    mounted() {
      for _ in $(seq 100); do
        if grep -q " $1 .* - fuse[. ]" /proc/self/mountinfo; then return 0; fi
        sleep 0.1
      done
      echo "$1 did not mount" >&2
      return 1
    }
    mkdir -p "$D/fuse-go" "$D/fuse-go-cipher" "$D/fuse-bind" "$D/fuse-bind-src"
    gocryptfs -init -q -scryptn 10 -extpass 'echo test-password' "$D/fuse-go-cipher" >/dev/null
    gocryptfs -q -fg -extpass 'echo test-password' -ko default_permissions,nodev,nosuid,noatime       "$D/fuse-go-cipher" "$D/fuse-go" &
    pid=$!
    mounted "$D/fuse-go"
    printf go-data > "$D/fuse-go/file"
    test "$(cat "$D/fuse-go/file")" = go-data
    hold go
    fusermount3 -u "$D/fuse-go"
    wait "$pid" || true
    if grep -q " $D/fuse-go " /proc/self/mountinfo; then echo "go mount survived -u" >&2; exit 1; fi
    printf from-source > "$D/fuse-bind-src/file"
    bindfs --no-allow-other -f "$D/fuse-bind-src" "$D/fuse-bind" &
    pid=$!
    mounted "$D/fuse-bind"
    test "$(cat "$D/fuse-bind/file")" = from-source
    printf written > "$D/fuse-bind/new"
    test "$(cat "$D/fuse-bind-src/new")" = written
    hold bind
    fusermount3 -u "$D/fuse-bind"
    wait "$pid" || true
    if grep -q " $D/fuse-bind " /proc/self/mountinfo; then echo "bind mount survived -u" >&2; exit 1; fi
  '';
  nodes = {
    sudo-approve =
      _:
      lib.recursiveUpdate baseNode (
        lib.recursiveUpdate (installPolicy sudoPolicy) {
          imports = [ module ];

          agent-sandbox = {
            enable = true;
            packages = sudoApprovePackages;

            policy = {
              interactiveApproval = false;
              uiBackend = "none";
            };

            sudoPolicy = "approve";
          };

          boot.kernelModules = [ "fuse" ];
        }
      );

    sudo-deny =
      _:
      baseNode
      // {
        imports = [ module ];

        agent-sandbox = {
          enable = true;
          packages = sudoDenyPackages;
          sudoPolicy = "deny";
        };
      };
  };
  scenarios = {
    # Approve mode executes the declaratively allowed command with arguments
    # but rejects sudo options.
    approve = {
      node = "sudo-approve";

      script = ''
        sudo_approve.wait_for_unit("multi-user.target")
        sudo_approve.wait_for_unit("agent-sandbox-vm-policy.service")
        sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", 'sudo id | grep -q "uid=0(root)"')
        sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "test \"$(sudo id -u)\" = 0")
        sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "sudo -u nobody id", expect_success=False)
        # One static sandbox launch with no gate: the first helper to reach
        # policyd, a sudo from a subshell, exits before a sibling subshell
        # runs its own sudo. Both reach the same session's approval path.
        sandbox_shell(
            sudo_approve,
            "sandbox-sudo-approve-bash",
            '(sudo id | grep -q "uid=0(root)") && (sudo id | grep -q "uid=0(root)")',
        )
      '';
    };

    # A command outside the declarative allow-list is queued for approval with
    # no UI to answer; the request must run into its ~60 s timeout and fail.
    approve-unlisted = {
      node = "sudo-approve";

      script = ''
        sudo_approve.wait_for_unit("multi-user.target")
        sudo_approve.wait_for_unit("agent-sandbox-vm-policy.service")
        sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "sudo sh -c id", expect_success=False)
      '';
    };

    # A pending sudo approval freezes the requesting sandbox like every other
    # prompt. Approving it thaws the sandbox before the command runs, so the
    # command reads the scope's cgroup.freeze as 0.
    approve-freeze = {
      node = "sudo-approve";

      script = ''
        sudo_approve.wait_for_unit("multi-user.target")
        sudo_approve.wait_for_unit("agent-sandbox-vm-policy.service")
        sudo_approve.wait_for_unit("user@1000.service")
        approve_cli = "runuser -u sandbox -- agent-sandbox-approve"
        sudo_approve.succeed(
            "systemd-run --unit=sudo-freeze --service-type=exec --working-directory=/home/user/sandbox-cwd "
            + "--setenv=PATH=/run/wrappers/bin:/run/current-system/sw/bin "
            + "runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 "
            + "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
            + "sandbox-sudo-approve-bash -c "
            + shlex.quote('test "$(sudo cat /run/sudo-freeze)" = 0')
        )
        sudo_approve.wait_until_succeeds(
            f"{approve_cli} pending | grep -F -q 'cat /run/sudo-freeze'", timeout=30
        )
        freeze_scope = sudo_approve.succeed(
            "pid=$(pgrep -f 'agent-sandbox-elevate.* cat /run/sudo-freeze$' | head -1); "
            + "awk -F: '$1 == 0 {print $3}' /proc/$pid/cgroup"
        ).strip()
        sudo_approve.succeed(f"test \"$(cat /sys/fs/cgroup{freeze_scope}/cgroup.freeze)\" = 1")
        sudo_approve.succeed(f"ln -s /sys/fs/cgroup{freeze_scope}/cgroup.freeze /run/sudo-freeze")
        freeze_prompt = sudo_approve.succeed(
            f"{approve_cli} pending | awk -F'\\t' '$2 == \"elevation\" && $5 ~ /sudo-freeze/ {{print $1; exit}}'"
        ).strip()
        sudo_approve.succeed(f"{approve_cli} approve {freeze_prompt} once")
        sudo_approve.wait_until_fails("systemctl is-active --quiet sudo-freeze.service", timeout=30)
        sudo_approve.fail("systemctl is-failed --quiet sudo-freeze.service")
      '';
    };

    # Sudo deny is an immediate guard failure.
    deny = {
      node = "sudo-deny";

      script = ''
        sudo_deny.wait_for_unit("multi-user.target")
        sandbox_shell(sudo_deny, "sandbox-sudo-deny-bash", 'sudo id 2>&1 | grep -q "sudo is disabled"')
      '';
    };

    # FUSE mounts through a static wrapper: the fusermount3 shim, on PATH for
    # go-fuse (gocryptfs) and at /run/wrappers/bin for libfuse (bindfs), has
    # policyd mount in the sandbox's mount namespace. Reads and writes go
    # through each mount, the host never sees it, and unmounting works.
    fuse = {
      node = "sudo-approve";

      script = ''
        sudo_approve.wait_for_unit("multi-user.target")
        sudo_approve.wait_for_unit("agent-sandbox-vm-policy.service")
        sudo_approve.succeed("rm -f /home/user/sandbox-readwrite/fuse-*")
        sudo_approve.succeed(
            "systemd-run --unit=fuse-static --service-type=exec --working-directory=/home/user/sandbox-cwd "
            + "--setenv=PATH=/run/wrappers/bin:/run/current-system/sw/bin "
            + "runuser -u sandbox -- sandbox-sudo-approve-fuse-bash -c "
            + shlex.quote(r"""${fuseScript}""")
        )

        def fuse_phase(name):
            try:
                sudo_approve.wait_until_succeeds(f"test -e /home/user/sandbox-readwrite/fuse-{name}-held", timeout=60)
            except Exception:
                print(sudo_approve.succeed("journalctl -u fuse-static.service --no-pager"))
                raise
            sudo_approve.fail("grep -E ' - fuse[. ]' /proc/self/mountinfo")
            sudo_approve.succeed(f"test -z \"$(ls /home/user/sandbox-readwrite/fuse-{name})\"")
            sudo_approve.succeed(f"touch /home/user/sandbox-readwrite/fuse-{name}-release")

        fuse_phase("go")
        fuse_phase("bind")
        sudo_approve.wait_until_fails("systemctl is-active --quiet fuse-static.service", timeout=60)
        sudo_approve.fail("systemctl is-failed --quiet fuse-static.service")
        sudo_approve.fail("grep -E ' - fuse[. ]' /proc/self/mountinfo")
      '';
    };
  };
in
{
  # Boots one VM for the group's parts, which must share a node, and runs
  # their scripts in order.
  mkCheck =
    name: parts:
    let
      node = scenarios.${builtins.head parts}.node;
      sameNode = builtins.all (part: scenarios.${part}.node == node) parts;
    in
    assert lib.assertMsg sameNode "approval-sudo group ${name} mixes nodes";
    pkgs.testers.runNixOSTest (_: {
      name = "e2e-approval-sudo-${name}";
      node.specialArgs = { inherit inputs; };
      nodes.${node} = nodes.${node};

      testScript = ''
        import shlex

        def sandbox_shell(node, package, script, *, expect_success=True):
            line = f"runuser -u sandbox -- {package} -c {shlex.quote(script)}"
            check = node.succeed if expect_success else node.fail
            return check(line, timeout=60)

        start_all()
        ${lib.concatMapStringsSep "\n" (part: scenarios.${part}.script) parts}
      '';
    });
}
