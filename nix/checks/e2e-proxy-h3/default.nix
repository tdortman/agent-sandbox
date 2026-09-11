{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e) proxyNode;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-proxy-h3";
  node.specialArgs = { inherit inputs; };
  nodes.proxy = proxyNode;

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

    for node in [proxy]:
        node.wait_for_unit("multi-user.target")

    # HTTP/3 policy is enforced per decoded request over IPv4 and IPv6.
    proxy.wait_for_unit("agent-sandbox-vm-h3-http.service", timeout=120)
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "python3 -c 'import socket; assert socket.getaddrinfo(\"h3-allowed.test\", 443); assert socket.getaddrinfo(\"h3-allowed-v6.test\", 443)'",
        wrapper=session_wrapper,
    )
    proxy.succeed("set +e; ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} reset counters table inet agent_sandbox_proxy_tproxy; runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus sandbox-proxy-bash -c 'curl --http3-only --cacert /run/agent-sandbox/proxy-ca-bundle.pem --fail --silent --show-error --max-time 15 https://h3-allowed.test:443/allowed | grep -q allowed-get' >/tmp/h3-allowed.log 2>&1; status=$?; cat /tmp/h3-allowed.log; ip netns exec agent-sandbox ip route get 169.254.100.1 mark 51820; ip netns exec agent-sandbox cat /proc/net/udp /proc/net/udp6; ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} -a list table inet agent_sandbox_proxy_tproxy; test $status -eq 0")
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "curl --http3-only --cacert /run/agent-sandbox/proxy-ca-bundle.pem --fail --silent --show-error --max-time 15 https://h3-allowed-v6.test:443/allowed | grep -q allowed-get",
        wrapper=session_wrapper,
    )
    # Raw or invalid UDP on intercepted HTTP/3 ports is rejected by the
    # proxy instead of egressing directly to the origin.
    proxy.succeed("before=$(grep -c '^datagram ' /var/log/h3-origin.log || true); set +e; runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus sandbox-proxy-bash -c 'printf blocked | timeout 3 socat - UDP4:169.254.100.1:443 | grep -q blocked' >/tmp/h3-raw-udp.log 2>&1; status=$?; set -e; cat /tmp/h3-raw-udp.log; sleep 1; after=$(grep -c '^datagram ' /var/log/h3-origin.log || true); test $status -ne 0; test \"$before\" = \"$after\"")

    proxy.succeed("before=$(grep -c '^datagram ' /var/log/h3-origin.log || true); set +e; runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus sandbox-proxy-bash -c 'printf blocked | timeout 3 socat - UDP4:169.254.100.1:4444 | grep -q blocked' >/tmp/h3-raw-alt-udp.log 2>&1; status=$?; set -e; cat /tmp/h3-raw-alt-udp.log; sleep 1; after=$(grep -c '^datagram ' /var/log/h3-origin.log || true); test $status -ne 0; test \"$before\" = \"$after\"")

    print(
        sandbox_shell(
            proxy,
            "sandbox-proxy-bash",
            "alt_svc=/tmp/h3-alt-svc-$$.cache; curl --http3-only --alt-svc \"$alt_svc\" --cacert /run/agent-sandbox/proxy-ca-bundle.pem --fail --silent --show-error --max-time 15 https://h3-allowed.test:443/allowed | grep -q allowed-get && cat \"$alt_svc\" && test -s \"$alt_svc\" && curl --http3 --alt-svc \"$alt_svc\" --cacert /run/agent-sandbox/proxy-ca-bundle.pem --fail --silent --show-error --max-time 15 https://h3-allowed.test:443/allowed | grep -q allowed-get",
            wrapper=session_wrapper,
        )
    )
    # Proxy mode gates UDP at the packet layer: new flows are queued for a
    # transport check (one prompt per host:port), then established flows
    # pass via conntrack.
    proxy.wait_for_unit("agent-sandbox-vm-udp-18082.service")
    proxy.wait_for_unit("agent-sandbox-vm-udp-18083.service")
    sandbox_shell(proxy, "sandbox-proxy-bash", "printf udp-ok | timeout 5 socat - UDP4:169.254.100.1:18082 | grep -q udp-ok", wrapper=session_wrapper)
    sandbox_shell(proxy, "sandbox-proxy-bash", "printf blocked | timeout 3 socat - UDP4:169.254.100.1:18083 | grep -q blocked", wrapper=session_wrapper, expect_success=False)
    proxy.succeed("journalctl --no-pager -b -u agent-sandbox-proxy.service | grep -F -q 'attributed alternative QUIC endpoint'")

    # The denied HTTP/3 request must complete as a clean 403 response.
    # A stream reset after the deny body would make curl exit non-zero.
    proxy.succeed("before=$(grep -F -c 'request GET /denied' /var/log/h3-origin.log || true); set +e; runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus sandbox-proxy-bash -c 'curl --http3-only --cacert /run/agent-sandbox/proxy-ca-bundle.pem --silent --show-error --max-time 15 https://h3-denied.test:443/denied' >/tmp/h3-denied.log 2>&1; status=$?; set -e; cat /tmp/h3-denied.log; after=$(grep -F -c 'request GET /denied' /var/log/h3-origin.log || true); test $status -eq 0; grep -F -q 'blocked by agent-sandbox policy' /tmp/h3-denied.log; test \"$before\" = \"$after\"")
  '';
})
