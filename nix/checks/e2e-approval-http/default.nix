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
    httpServers
    mkBash
    module
    tlsFixture
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-approval-http";
  node.specialArgs = { inherit inputs; };

  nodes.approval =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (httpServers [ { port = 8008; } ]) {
        imports = [ module ];

        agent-sandbox = {
          enable = true;

          network = {
            enable = true;

            # Raw TCP echo for the passthrough happy path: the proxy
            # sniffs non-HTTP bytes and splices after this rule allows.
            declarativeAllow = [
              {
                host = "169.254.100.1";
                port = 18084;
              }
            ];

            dnsForwardTarget = "169.254.100.1:5353";

            httpProxy = {
              enable = true;
              caCertificateFile = "${tlsFixture}/ca-cert.pem";
              caPrivateKeyFile = "${tlsFixture}/ca-key.pem";
              upstreamAllowCidrs = [ "169.254.100.1/32" ];
            };
          };

          packages = [
            (mkBash "sandbox-approve-bash" {
              extraPkgs = commonExtraPkgs ++ [ pkgs.curl ];
            })
            (mkBash "sandbox-approve-other-bash" {
              extraPkgs = commonExtraPkgs ++ [ pkgs.curl ];
            })
          ];

          # Pending requests are recorded but no UI is spawned; the
          # scenario resolves them with agent-sandbox-approve.
          policy.uiBackend = "none";
        };

        networking.firewall.interfaces.asbx-test-host.allowedTCPPorts = [
          8008
          18084
          18085
        ];

        systemd.services = {
          agent-sandbox-vm-dns = {
            after = [ "agent-sandbox-netns.service" ];
            requires = [ "agent-sandbox-netns.service" ];
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = lib.escapeShellArgs [
                "${pkgs.dnsmasq}/bin/dnsmasq"
                "--keep-in-foreground"
                "--no-resolv"
                "--no-hosts"
                "--bind-interfaces"
                "--listen-address=169.254.100.1"
                "--port=5353"
                "--user=sandbox"
              ];

              Restart = "on-failure";
            };
          };

          agent-sandbox-vm-tcp-18084 = {
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:18084,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
              Restart = "on-failure";
              User = "sandbox";
            };
          };

          agent-sandbox-vm-tcp-18085 = {
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:18085,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
              Restart = "on-failure";
              User = "sandbox";
            };
          };
        };
      }
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

    for node in [approval]:
        node.wait_for_unit("multi-user.target")

    # Runtime approval flow: an unapproved URL pends, the per-package
    # approval persists a package-scoped rule, other packages stay
    # isolated, and a once-scoped deny resolves only its own request.
    approval.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
    approval.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
    approval.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
    approval.wait_for_unit("agent-sandbox-policy.service")
    approval.wait_for_open_port(8008)
    approval.succeed(
        "test \"$(runuser -u sandbox -- agent-sandbox-approve pending)\" = 'No pending approvals.'"
    )

    approve_env = ["env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"]
    pending_http_id = "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"http\" {print $1; exit}'"

    def package_cmd(package, script, *, background=False):
        # The wrapper records $PWD as the project root, so the sandboxed
        # command runs from the sandbox user's home for the package rule
        # to land in a predictable project file.
        inner = f"cd /home/user && {shlex.join([package, '-c', script])}"
        if background:
            # Fully detach stdio so the test driver's shell prompt returns
            # immediately instead of waiting on the sandbox's inherited fds.
            detached = (
                "nohup runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 "
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
                f"sh -c {shlex.quote(inner)} </dev/null >/tmp/approve-bg.out 2>&1 &"
            )
            return command("sh", "-c", detached)
        return command("runuser", "-u", "sandbox", "--", *approve_env, "sh", "-c", inner)

    # The first request from the package pends; approving it at
    # project_package scope lets the held connection complete.
    approval.succeed(
        package_cmd("sandbox-approve-bash", "curl --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed", background=True)
    )
    approval.wait_until_succeeds(
        "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/allowed'"
    )
    allowed_id = approval.succeed(pending_http_id).strip()
    assert "http:" in allowed_id, allowed_id
    approval.succeed(
        f"runuser -u sandbox -- agent-sandbox-approve approve {allowed_id} project_package"
    )
    approval.wait_until_succeeds("grep -q allowed-get /tmp/approve-bg.out")

    # The rule persists to the package-specific project file and applies
    # to later requests from the same package without a prompt.
    approval.succeed("test -f /home/user/.agent-sandbox/packages/sandbox-approve-bash.json")
    approval.succeed(
        "grep -F -q '\"url\": \"http://169.254.100.1/allowed\"' /home/user/.agent-sandbox/packages/sandbox-approve-bash.json"
    )
    approval.succeed(
        "grep -F -q '\"port\": 8008' /home/user/.agent-sandbox/packages/sandbox-approve-bash.json"
    )
    approval.succeed(
        package_cmd("sandbox-approve-bash", "curl --fail --silent --show-error --max-time 15 http://169.254.100.1:8008/allowed | grep -q allowed-get")
    )
    approval.succeed(
        "runuser -u sandbox -- agent-sandbox-approve pending | grep -v -F 'http://169.254.100.1:8008/allowed'"
    )

    # Another package is not covered by the rule: its request to the same
    # approved URL pends separately, and a once-scoped deny blocks only
    # that request without persisting.
    approval.succeed(
        package_cmd("sandbox-approve-other-bash", "curl --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed", background=True)
    )
    approval.wait_until_succeeds(
        "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/allowed'"
    )
    other_id = approval.succeed(pending_http_id).strip()
    approval.succeed(f"runuser -u sandbox -- agent-sandbox-approve deny {other_id} once")
    approval.wait_until_succeeds("grep -F -q 'blocked by agent-sandbox policy' /tmp/approve-bg.out")

    # The once deny did not persist: the same request pends again.
    approval.succeed(
        package_cmd("sandbox-approve-other-bash", "curl --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed", background=True)
    )
    approval.wait_until_succeeds(
        "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/allowed'"
    )
  '';
})
