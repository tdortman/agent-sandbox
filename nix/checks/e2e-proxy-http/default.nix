{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e) proxyNode tlsFixture;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-proxy-http";
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

    # Transparent HTTP(S) policy: exercise the allow, deny, TLS, and
    # streaming contracts through the transparent proxy.
    print(proxy.succeed("systemctl --no-pager --full status agent-sandbox-proxy.service agent-sandbox-proxy-route.service agent-sandbox-nfq.service agent-sandbox-dns.service agent-sandbox-netns.service agent-sandbox-policy.service agent-sandbox-proxy-firewall.service agent-sandbox-proxy-init.service || true"))
    print(proxy.succeed("systemctl --failed --no-legend || true; journalctl --no-pager -b -u agent-sandbox-proxy-route.service -u agent-sandbox-nfq.service -u agent-sandbox-dns.service -u agent-sandbox-netns.service -u agent-sandbox-policy.service || true"))
    proxy.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
    proxy.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
    proxy.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
    check_loopback_bridge(proxy, "sandbox-proxy-bash", wrapper=session_wrapper)
    print(proxy.succeed("ip netns exec agent-sandbox sh -c 'ip rule show; ip route show table 51820' || true"))
    print(proxy.succeed("systemctl show --property=MainPID,ActiveState,SubState,ExecMainCode,ExecMainStatus agent-sandbox-proxy.service; systemctl --no-pager --full status agent-sandbox-proxy.service || true"))
    print(proxy.succeed("ip netns exec agent-sandbox sh -c 'cat /proc/net/tcp; cat /proc/net/tcp6'"))
    print(proxy.succeed("ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} -a list table inet agent_sandbox_proxy_tproxy"))
    proxy.wait_for_unit("user@1000.service")
    proxy.wait_for_open_port(8008)
    proxy.wait_for_open_port(8080)
    proxy.wait_for_open_port(8443)
    proxy.succeed("curl --fail --silent -X POST http://127.0.0.1:8008/allowed | grep -q post-ok")
    proxy.succeed("curl --fail --silent http://127.0.0.1:8008/unlisted | grep -q unlisted-get")
    proxy.succeed("curl --fail --silent --cacert ${tlsFixture}/ca-cert.pem https://169.254.100.1:8443/allowed | grep -q allowed-get")
    sandbox_shell(proxy, "sandbox-proxy-bash", "test \"$SSL_CERT_FILE\" = /run/agent-sandbox/proxy-ca-bundle.pem && test \"$NODE_EXTRA_CA_CERTS\" = /run/agent-sandbox/proxy-ca-bundle.pem && test -r \"$SSL_CERT_FILE\"", wrapper=session_wrapper)
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "cmp -s /etc/ssl/certs/ca-certificates.crt /run/agent-sandbox/proxy-ca-bundle.pem && cmp -s /etc/ssl/certs/ca-bundle.crt /run/agent-sandbox/proxy-ca-bundle.pem",
        wrapper=session_wrapper,
    )
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "env -u SSL_CERT_FILE -u CURL_CA_BUNDLE -u REQUESTS_CA_BUNDLE -u NODE_EXTRA_CA_CERTS curl --fail --silent --show-error --max-time 30 https://169.254.100.1:8443/allowed | grep -q allowed-get",
        wrapper=session_wrapper,
    )
    print(proxy.succeed("ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} -a list table inet agent_sandbox"))
    print(proxy.succeed("ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} -a list ruleset"))
    sandbox_shell(proxy, "sandbox-proxy-bash", "curl --fail --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed | grep -q allowed-get", wrapper=session_wrapper)
    sandbox_shell(proxy, "sandbox-proxy-bash", "curl --fail --silent --show-error --max-time 30 http://169.254.100.1:8080/allowed | grep -q allowed-get", wrapper=session_wrapper)
    sandbox_shell(proxy, "sandbox-proxy-bash", "curl --fail --silent --show-error --max-time 30 https://169.254.100.1:8443/allowed | grep -q allowed-get", wrapper=session_wrapper)
    sandbox_shell(proxy, "sandbox-proxy-bash", "timeout 3 curl --no-buffer --fail --silent --show-error 'http://169.254.100.1:8008/stream?alt=sse' | grep -q 'data: first'", wrapper=session_wrapper)
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "status=$(curl --silent --show-error --max-time 15 --dump-header /tmp/proxy-denied-http.headers --output /tmp/proxy-denied-http.body --write-out '%{http_code}' http://169.254.100.1:8008/denied); test \"$status\" = 403 && grep -F -q 'x-agent-sandbox-policy: blocked' /tmp/proxy-denied-http.headers && grep -F -x -q 'blocked by agent-sandbox policy' /tmp/proxy-denied-http.body",
        wrapper=session_wrapper,
    )
    sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "-X", "POST", "http://169.254.100.1:8008/denied", wrapper=session_wrapper, expect_success=False)
    sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "-X", "POST", "http://169.254.100.1:8008/allowed", wrapper=session_wrapper, expect_success=False)
    sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "http://169.254.100.1:8008/unlisted", wrapper=session_wrapper, expect_success=False)
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "status=$(curl --silent --show-error --max-time 15 --dump-header /tmp/proxy-denied-https.headers --output /tmp/proxy-denied-https.body --write-out '%{http_code}' https://169.254.100.1:8443/denied); test \"$status\" = 403 && grep -F -q 'x-agent-sandbox-policy: blocked' /tmp/proxy-denied-https.headers && grep -F -x -q 'blocked by agent-sandbox policy' /tmp/proxy-denied-https.body",
        wrapper=session_wrapper,
    )
    sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "-X", "POST", "https://169.254.100.1:8443/allowed", wrapper=session_wrapper, expect_success=False)
    sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "https://169.254.100.1:8443/unlisted", wrapper=session_wrapper, expect_success=False)


    # TLS identity: the SNI must match the origin certificate. The policy
    # target is allowed, but the certificate carries only IP SANs, so the
    # upstream handshake must fail closed.
    sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "https://allowed.test:8443/allowed", wrapper=session_wrapper, expect_success=False)
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "curl --silent --show-error --max-time 15 -o /dev/null -w '%{http_code}' https://allowed.test:8443/allowed | grep -q 502",
        wrapper=session_wrapper,
    )

  '';
})
