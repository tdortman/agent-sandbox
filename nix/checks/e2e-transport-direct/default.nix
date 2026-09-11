{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e)
    baseNode
    directNetworkPackages
    httpServers
    loopbackPorts
    loopbackServices
    module
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-transport-direct";
  node.specialArgs = { inherit inputs; };

  nodes.direct =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate
        (httpServers (
          (map (port: { inherit port; }) [
            18080
            18081
            18086
            18087
            18088
          ])
          ++ (map
            (port: {
              inherit port;
              address = "::";
              serviceName = "http6";
            })
            [
              18084
              18085
            ]
          )
        ))
        {
          imports = [ module ];

          agent-sandbox = {
            enable = true;
            gates.syscalls.enable = true;

            network = {
              enable = true;

              declarativeAllow = [
                {
                  host = "169.254.100.1";
                  port = 18080;
                }
                {
                  host = "169.254.100.1";
                  port = 18082;
                }
                {
                  host = "fd00:dead:beef::1";
                  port = 18084;
                }
                {
                  host = "allowed.test";
                  port = 18086;
                }
              ];

              declarativeDeny = [
                {
                  host = "169.254.100.1";
                  port = 18081;
                }
                {
                  host = "169.254.100.1";
                  port = 18083;
                }
                {
                  host = "fd00:dead:beef::1";
                  port = 18085;
                }
                {
                  host = "denied.test";
                  port = 18087;
                }
              ];

              dnsForwardTarget = "169.254.100.1:5353";
              loopback = loopbackPorts;
            };

            packages = directNetworkPackages;

            policy = {
              interactiveApproval = false;
              uiBackend = "none";
            };
          };

          systemd.services = loopbackServices // {
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
                  "--address=/allowed.test/169.254.100.1"
                  "--address=/denied.test/169.254.100.1"
                ];

                Restart = "on-failure";
              };
            };

            agent-sandbox-vm-udp-18082 = {
              wantedBy = [ "multi-user.target" ];

              serviceConfig = {
                ExecStart = "${pkgs.socat}/bin/socat UDP4-RECVFROM:18082,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
                Restart = "on-failure";
                User = "sandbox";
              };
            };

            agent-sandbox-vm-udp-18083 = {
              wantedBy = [ "multi-user.target" ];

              serviceConfig = {
                ExecStart = "${pkgs.socat}/bin/socat UDP4-RECVFROM:18083,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
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

    for node in [direct]:
        node.wait_for_unit("multi-user.target")

    # Direct transport policy: declared TCP and UDP ports are reachable,
    # while denied ports with listening backends remain unreachable.
    direct.wait_for_unit("agent-sandbox-netns.service")
    direct.wait_for_unit("agent-sandbox-policy.service")
    direct.wait_for_unit("agent-sandbox-vm-dns.service")
    sandbox_shell(direct, "sandbox-direct-bash", "grep -Eq '^Seccomp_filters:[[:space:]]*[1-9][0-9]*$' /proc/self/status")
    direct.wait_for_open_port(18080)
    direct.wait_for_open_port(18081)
    direct.wait_for_unit("agent-sandbox-vm-udp-18082.service")
    direct.wait_for_unit("agent-sandbox-vm-udp-18083.service")
    direct.wait_for_unit("agent-sandbox-vm-http6-18084.service")
    direct.wait_for_unit("agent-sandbox-vm-http6-18085.service")
    direct.succeed("curl --noproxy '*' --fail --silent 'http://[::1]:18084/allowed' | grep -q allowed-get")
    direct.succeed("curl --noproxy '*' --fail --silent 'http://[::1]:18085/allowed' | grep -q allowed-get")
    direct.wait_for_open_port(18086)
    direct.wait_for_open_port(18087)
    direct.wait_for_open_port(18088)
    check_loopback_bridge(direct, "sandbox-direct-bash")
    sandbox_shell(direct, "sandbox-direct-bash", "curl --fail --silent --show-error --max-time 15 http://169.254.100.1:18080/readonly-file | grep -q readonly-file-marker")
    sandbox_exec(direct, "sandbox-direct-curl", "--silent", "--show-error", "--max-time", "5", "http://169.254.100.1:18081/readonly-file", expect_success=False)
    sandbox_shell(direct, "sandbox-direct-bash", "printf udp-ok | timeout 5 socat - UDP4:169.254.100.1:18082 | grep -q udp-ok")
    sandbox_shell(direct, "sandbox-direct-bash", "printf blocked | timeout 3 socat - UDP4:169.254.100.1:18083 | grep -q blocked", expect_success=False)
    sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --fail --silent --show-error --max-time 15 'http://[fd00:dead:beef::1]:18084/allowed' | grep -q allowed-get")
    sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --fail --silent --show-error --max-time 5 'http://[fd00:dead:beef::1]:18085/allowed'", expect_success=False)
    sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --fail --silent --show-error --max-time 15 http://allowed.test:18086/allowed | grep -q allowed-get")
    sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --silent --show-error --max-time 5 http://denied.test:18087/denied", expect_success=False)
    sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --silent --show-error --max-time 5 http://169.254.100.1:18088/unlisted", expect_success=False)
  '';
})
