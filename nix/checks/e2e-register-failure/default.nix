{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e)
    baseNode
    dynamicPolicy
    installPolicy
    mkBash
    module
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };

  # Two packages that may not share a session.
  packages = [
    (mkBash "register-first-bash" { extraPkgs = e2e.commonExtraPkgs; })
    (mkBash "register-second-bash" { extraPkgs = e2e.commonExtraPkgs; })
  ];
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-register-failure";
  node.specialArgs = { inherit inputs; };

  nodes.dynamic =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (installPolicy dynamicPolicy) {
        imports = [ module ];

        agent-sandbox = {
          inherit packages;
          enable = true;

          gates = {
            filesystem.enable = true;
            syscalls.enable = true;
          };

          policy = {
            interactiveApproval = false;
            uiBackend = "none";
          };
        };
      }
    );

  testScript = ''
    import shlex

    SESSION = "register-failure-session"
    MARKER = "/var/lib/agent-sandbox-test/dynamic-mutations/second-ran"

    def sandbox(package, session, script):
        env = [
            "XDG_RUNTIME_DIR=/run/user/1000",
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
            f"AGENT_SANDBOX_SESSION_ID={session}",
        ]
        inner = f"cd /home/user && {shlex.join([package, '-c', script])}"
        return shlex.join(["runuser", "-u", "sandbox", "--", "env", *env, "sh", "-c", inner])

    start_all()
    dynamic.wait_for_unit("multi-user.target")
    dynamic.wait_for_unit("agent-sandbox-policy.socket")
    dynamic.wait_for_unit("agent-sandbox-policy.service")
    dynamic.wait_for_unit("user@1000.service")

    # A first sandbox registers the session for its package and keeps running.
    dynamic.succeed(
        "nohup " + sandbox("register-first-bash", SESSION, "exec sleep 600")
        + " </dev/null >/tmp/first.out 2>&1 &"
    )
    dynamic.wait_until_succeeds("pgrep -u sandbox -x sleep", timeout=60)

    # A sandbox of another package names the same session. policyd refuses
    # to attribute one session to two packages, so the registration fails and
    # the launch fails with it: the command never runs.
    status, output = dynamic.execute(sandbox("register-second-bash", SESSION, ": > " + MARKER) + " 2>&1")
    assert status != 0, f"a failed registration did not stop the launch: {output}"
    assert "did not register this sandbox session" in output, output
    dynamic.fail("test -e " + MARKER)

    # With a session of its own the same package registers and runs, so the
    # refusal above came from the registration alone.
    dynamic.succeed(sandbox("register-second-bash", "register-failure-other", ": > " + MARKER), timeout=60)
    dynamic.succeed("test -e " + MARKER)
  '';
})
