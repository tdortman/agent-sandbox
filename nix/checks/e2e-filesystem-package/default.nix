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
    installHomePolicy
    installPolicy
    mkBash
    module
    packageExtension
    packagePolicy
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-filesystem-package";
  node.specialArgs = { inherit inputs; };

  nodes.package =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (installPolicy packagePolicy) (
        lib.recursiveUpdate
          (installHomePolicy "pkg-extension" {
            content = packageExtension;
            path = "/home/user/agent-sandbox-pkg-link-target/extension.json";
            symlink = "/home/user/.config/agent-sandbox/packages/sandbox-pkg-allowed-bash.json";
          })
          {
            imports = [ module ];

            agent-sandbox = {
              enable = true;
              gates.filesystem.enable = true;

              packages = [
                (mkBash "sandbox-pkg-allowed-bash" {
                  extraPkgs = commonExtraPkgs;

                  policy.filesystem = {
                    allow = [
                      {
                        access = "read";
                        path = "/var/lib/agent-sandbox-test/pkg-allowed-marker";
                      }
                    ];

                    deny = [
                      {
                        access = "all";
                        path = "/var/lib/agent-sandbox-test/pkg-denied-marker";
                      }
                    ];
                  };
                })

                (mkBash "sandbox-pkg-other-bash" {
                  extraPkgs = commonExtraPkgs;

                  policy.filesystem.deny = [
                    {
                      access = "all";
                      path = "/var/lib/agent-sandbox-test/pkg-global-marker";
                    }
                  ];
                })
              ];

              policy = {
                interactiveApproval = false;
                uiBackend = "none";
              };
            };
          }
      )
    );

  testScript = ''
    import shlex

    def command(*args):
        return shlex.join(str(arg) for arg in args)

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

    for node in [package]:
        node.wait_for_unit("multi-user.target")

    # Per-package policy: declarative base files, the user-writable home
    # extension (symlinked), deny-wins, cross-package isolation, and
    # in-sandbox read/write protection of the policy files.
    package.wait_for_unit("agent-sandbox-policy.service")
    package.succeed(
        "test -f /etc/agent-sandbox/packages/sandbox-pkg-allowed-bash.json && test -f /etc/agent-sandbox/packages/sandbox-pkg-other-bash.json"
    )
    # Declared base allow and deny apply without a prompt.
    sandbox_shell(package, "sandbox-pkg-allowed-bash", "grep -q pkg-allowed-marker /var/lib/agent-sandbox-test/pkg-allowed-marker")
    sandbox_shell(package, "sandbox-pkg-allowed-bash", "cat /var/lib/agent-sandbox-test/pkg-denied-marker >/dev/null", expect_success=False)
    # Cross-package isolation: the other package has no rule for the marker.
    sandbox_shell(package, "sandbox-pkg-other-bash", "cat /var/lib/agent-sandbox-test/pkg-allowed-marker >/dev/null", expect_success=False)
    # Deny-wins: the user policy allows the marker, the package deny shadows it.
    sandbox_shell(package, "sandbox-pkg-other-bash", "cat /var/lib/agent-sandbox-test/pkg-global-marker >/dev/null", expect_success=False)
    sandbox_shell(package, "sandbox-pkg-allowed-bash", "grep -q pkg-global-marker /var/lib/agent-sandbox-test/pkg-global-marker")
    # The symlinked home extension is loaded and its allow applies.
    sandbox_shell(package, "sandbox-pkg-allowed-bash", "grep -q pkg-ext-marker /var/lib/agent-sandbox-test/pkg-ext-marker")
    # The declarative base and the home extension are unreadable in-sandbox.
    sandbox_shell(package, "sandbox-pkg-allowed-bash", "cat /etc/agent-sandbox/packages/sandbox-pkg-allowed-bash.json >/dev/null", expect_success=False)
    sandbox_shell(package, "sandbox-pkg-allowed-bash", "cat ~/.config/agent-sandbox/packages/sandbox-pkg-allowed-bash.json >/dev/null", expect_success=False)
    # Reading through the resolved symlink target must also be denied. The
    # monitor sees the real path after the kernel resolves the link, so the
    # deny must follow the symlink to its target inode.
    sandbox_shell(package, "sandbox-pkg-allowed-bash", "cat /home/user/agent-sandbox-pkg-link-target/extension.json >/dev/null", expect_success=False)
    # A write through the symlinked extension is blocked (ro-bound target).
    sandbox_shell(package, "sandbox-pkg-allowed-bash", "printf changed >> ~/.config/agent-sandbox/packages/sandbox-pkg-allowed-bash.json", expect_success=False)
  '';
})
