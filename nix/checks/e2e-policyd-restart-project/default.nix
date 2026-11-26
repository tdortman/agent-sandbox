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
  name = "e2e-policyd-restart-project";
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

          packages = dynamicPackages;

          policy = {
            interactiveApproval = false;
            uiBackend = "none";
          };
        };
      }
    );

  testScript = ''
    import json
    import shlex

    base = "/var/lib/agent-sandbox-test"
    early = base + "/project-early"
    late = base + "/project-late"
    probe_log = base + "/dynamic-mutations/project-probe.log"
    project = "/home/user/sandbox-cwd"
    policy = project + "/.agent-sandbox/policy.json"

    def as_sandbox_user(*args):
        return shlex.join(["runuser", "-u", "sandbox", "--", *args])

    def project_policy(*paths):
        return json.dumps({"filesystem": {"allow": [{"path": path, "access": "read"} for path in paths]}})

    def write_policy(*paths):
        dynamic.succeed(as_sandbox_user("sh", "-c", f"printf %s {shlex.quote(project_policy(*paths))} > {policy}"))

    def wait_latest(name, state, timeout=60):
        dynamic.wait_until_succeeds(f"test \"$(grep '^{name} ' {probe_log} | tail -n 1)\" = '{name} {state}'", timeout=timeout)

    start_all()
    dynamic.wait_for_unit("multi-user.target")
    dynamic.wait_for_unit("agent-sandbox-policy.socket")
    dynamic.wait_for_unit("agent-sandbox-policy.service")
    # The sandbox must start in its own scope, so the lingering user manager
    # has to be up first.
    dynamic.wait_for_unit("user@1000.service")

    # Two files only the project's policy may open. The project allows one now
    # and the other once the daemon has restarted.
    dynamic.succeed(f"printf early > {early} && printf late > {late}")
    dynamic.succeed(as_sandbox_user("mkdir", "-p", project + "/.agent-sandbox"))
    write_policy(early)

    # A long-lived sandbox of that project tries both files every moment.
    probe = (
        "while :; do for name in early late; do "
        f"if cat {base}/project-$name >/dev/null 2>&1; then echo \"$name ok\"; else echo \"$name denied\"; fi; "
        f"done >> {probe_log}; sleep 0.3; done"
    )
    launch = (
        f"cd {project} && exec "
        + as_sandbox_user(
            "env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
            "sandbox-dynamic-bash", "-c", probe,
        )
    )
    dynamic.succeed(shlex.join([
        "systemd-run", "--unit=project-probe", "--service-type=exec",
        "--setenv=PATH=/run/wrappers/bin:/run/current-system/sw/bin",
        "sh", "-c", launch + " </dev/null >/dev/null 2>/tmp/project-probe-errors",
    ]))

    try:
        wait_latest("early", "ok")
    except Exception:
        print(dynamic.succeed("cat /tmp/project-probe-errors; cat " + probe_log + " || true"))
        raise
    wait_latest("late", "denied")

    def sandbox_pids():
        return sorted(dynamic.succeed("pgrep -u sandbox -f 'project-\\$name'").split())

    before = sandbox_pids()
    assert before, "the probe sandbox is not running"

    dynamic.succeed("systemctl restart agent-sandbox-policy.service")
    dynamic.wait_for_unit("agent-sandbox-policy.service")
    assert sandbox_pids() == before, "the restart replaced the running sandbox"

    # The running sandbox is still attributed to its session and project: a
    # rule added to its project policy after the restart applies to it, and
    # the rule it already had still does.
    write_policy(early, late)
    try:
        wait_latest("late", "ok")
    except Exception:
        print(dynamic.succeed("tail -n 20 " + probe_log + "; journalctl -u agent-sandbox-policy.service --no-pager | tail -n 40"))
        raise
    wait_latest("early", "ok")
  '';
})
