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
  name = "e2e-approval-freeze";
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

    approval.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
    approval.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
    approval.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
    approval.wait_for_unit("agent-sandbox-policy.service")
    approval.wait_for_open_port(8008)

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

    # Raw TCP passthrough: non-HTTP bytes on an unusual port take the
    # checked splice instead of the HTTP path. Port 18084 has a
    # declarative rule, so this completes with no prompt at all.
    approval.wait_for_unit("agent-sandbox-vm-tcp-18084.service")
    approval.wait_for_unit("agent-sandbox-vm-tcp-18085.service")
    approval.succeed(
        package_cmd("sandbox-approve-bash", "printf passthrough-ok | socat -T 10 - TCP4:169.254.100.1:18084 | grep -q passthrough-ok")
    )
    approval.succeed(
        "test \"$(runuser -u sandbox -- agent-sandbox-approve pending | grep -c -F '169.254.100.1:18084')\" = 0"
    )

    # A frozen clock still ticks, so the assertions below pin the
    # mechanism (cgroup.freeze reads 1 mid-prompt), not the absence of
    # time: the freeze stops fail-fast spins and holds the connection
    # open, and the client recovers on thaw. Port 18085 has no rule.
    approval.succeed(
        package_cmd("sandbox-approve-bash", "printf freeze-probe | socat - TCP4:169.254.100.1:18085", background=True)
    )
    approval.wait_until_succeeds(
        "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q '169.254.100.1:18085'"
    )
    approval.wait_until_succeeds(
        "pid=$(pgrep -f '^[^ ]*socat .*TCP4:169.254.100.1:18085' | head -1); "
        "scope=$(awk -F: '$1 == 0 {print $3}' /proc/$pid/cgroup); "
        "test \"$(cat /sys/fs/cgroup$scope/cgroup.freeze)\" = 1"
    )
    approval.succeed("sleep 10")
    tcp_id = approval.succeed(
        "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"network\" && $5 == \"169.254.100.1:18085\" {print $1; exit}'"
    ).strip()
    assert "net:" in tcp_id, tcp_id
    approval.succeed(f"runuser -u sandbox -- agent-sandbox-approve approve {tcp_id} once")
    approval.wait_until_succeeds("grep -q freeze-probe /tmp/approve-bg.out")

    # HTTP approvals freeze the same way. /unlisted has no rule for this
    # package, so it prompts; the delayed approval still completes.
    approval.succeed(
        package_cmd("sandbox-approve-bash", "curl --silent --show-error --max-time 30 http://169.254.100.1:8008/unlisted", background=True)
    )
    approval.wait_until_succeeds(
        "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/unlisted'"
    )
    approval.wait_until_succeeds(
        "pid=$(pgrep -f '^[^ ]*curl .*8008/unlisted' | head -1); "
        "scope=$(awk -F: '$1 == 0 {print $3}' /proc/$pid/cgroup); "
        "test \"$(cat /sys/fs/cgroup$scope/cgroup.freeze)\" = 1"
    )
    approval.succeed("sleep 10")
    http_id = approval.succeed(
        "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"http\" && $5 ~ /unlisted/ {print $1; exit}'"
    ).strip()
    approval.succeed(f"runuser -u sandbox -- agent-sandbox-approve approve {http_id} once")
    approval.wait_until_succeeds("grep -q unlisted-get /tmp/approve-bg.out")
  '';
})
