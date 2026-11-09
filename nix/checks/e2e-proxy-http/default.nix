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

  nodes.proxy = lib.recursiveUpdate proxyNode {
    # A system update that changes policyd and every proxy unit.
    specialisation.changed-proxy.configuration.systemd.services =
      lib.genAttrs
        [
          "agent-sandbox-dns"
          "agent-sandbox-policy"
          "agent-sandbox-proxy"
          "agent-sandbox-proxy-firewall"
          "agent-sandbox-proxy-init"
          "agent-sandbox-proxy-route"
        ]
        (_: {
          environment.AGENT_SANDBOX_TEST_GENERATION = "changed";
        });
  };

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
    # The in-kernel verdict gate: the object loads and pins, the attach leaves
    # no fail-soft diagnostic behind, and nfq opens both pinned maps. nfq only
    # reports the cache as enabled after the map types and sizes match the Rust
    # layout contract, so this line is the C and Rust layouts agreeing.
    proxy.succeed("test -e /sys/fs/bpf/agent-sandbox-verdict/verdicts")
    proxy.succeed("test -e /sys/fs/bpf/agent-sandbox-verdict/namespace_state")
    proxy.succeed(
        "! journalctl --no-pager -b -u agent-sandbox-verdict-gate.service | grep -q 'continuing without kernel-side denial'"
    )
    proxy.succeed(
        "journalctl --no-pager -b -u agent-sandbox-nfq.service | grep -q 'verdict cache enabled'"
    )
    check_loopback_bridge(proxy, "sandbox-proxy-bash", wrapper=session_wrapper)
    # Unlisted host localhost ports: policy decides per port.
    proxy.wait_for_open_port(18094)
    proxy.wait_for_open_port(18095)
    proxy.wait_for_unit("agent-sandbox-vm-localhost-udp-18096.service")
    sandbox_shell(proxy, "sandbox-proxy-bash", "timeout 5 socat - TCP4:127.0.0.1:18094 </dev/null | grep -q host-18094", wrapper=session_wrapper)
    sandbox_shell(proxy, "sandbox-proxy-bash", "timeout 5 socat - TCP4:127.0.0.1:18095 </dev/null | grep -q host-18095", wrapper=session_wrapper, expect_success=False)
    sandbox_shell(proxy, "sandbox-proxy-bash", "printf host-udp-18096 | timeout 5 socat - UDP4:127.0.0.1:18096 | grep -q host-udp-18096", wrapper=session_wrapper)
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
    sandbox_shell(proxy, "sandbox-proxy-bash", "test \"$SSL_CERT_FILE\" = /run/agent-sandbox/shared/proxy-ca-bundle.pem && test \"$NODE_EXTRA_CA_CERTS\" = /run/agent-sandbox/shared/proxy-ca-bundle.pem && test -r \"$SSL_CERT_FILE\"", wrapper=session_wrapper)
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "cmp -s /etc/ssl/certs/ca-certificates.crt /run/agent-sandbox/shared/proxy-ca-bundle.pem && cmp -s /etc/ssl/certs/ca-bundle.crt /run/agent-sandbox/shared/proxy-ca-bundle.pem",
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

    # One keep-alive connection, held by a running sandbox, sends a request
    # before and after a policyd restart and a system switch. Each request
    # needs the proxy's claim on that connection, so it answers only if the
    # proxy kept running and resumed its policy session.
    proxy.succeed("mkfifo -m 0666 /tmp/keepalive-input")
    keepalive = (
        "exec 4<>/dev/tcp/169.254.100.1/8008; "
        "while read -r token; do "
        "printf 'GET /allowed HTTP/1.1\\r\\nHost: 169.254.100.1:8008\\r\\n\\r\\n' >&4; "
        "status=; body=; "
        "read -r -t 15 status <&4 && "
        "while read -r -t 15 header <&4 && [ \"$header\" != $'\\r' ]; do :; done && "
        "read -r -t 15 body <&4; "
        "printf '%s %s %s\\n' \"$token\" \"$body\" \"$status\"; done"
    )
    launch = command("runuser", "-u", "sandbox", "--", *session_wrapper, "sandbox-proxy-bash", "-c", keepalive)
    # Detached from the driver's console, which a backgrounded runuser holds.
    detached = "exec " + launch + " < /tmp/keepalive-input > /tmp/keepalive-output 2>/tmp/keepalive-errors"
    proxy.succeed(command("setsid", "-f", "sh", "-c", detached) + " </dev/null >/dev/null 2>&1")
    proxy.succeed("sh -c 'exec 3>/tmp/keepalive-input; sleep 600' >/dev/null 2>&1 &")

    def keepalive_request(token):
        proxy.succeed(command("printf", "%s\\n", token) + " > /tmp/keepalive-input")
        try:
            proxy.wait_until_succeeds(command("grep", "-q", "^" + token + " ", "/tmp/keepalive-output"), timeout=60)
        except Exception:
            print(proxy.succeed("cat /tmp/keepalive-errors"))
            raise
        line = proxy.succeed(command("grep", "^" + token + " ", "/tmp/keepalive-output")).strip()
        assert line.startswith(token + " allowed-get") and " 200 " in line, f"keep-alive request {token}: {line!r}"

    def unit(prop, name):
        return proxy.succeed(command("systemctl", "show", "-p", prop, "--value", name)).strip()

    keepalive_request("before")
    proxy_pid = unit("MainPID", "agent-sandbox-proxy.service")
    route_invocation = unit("InvocationID", "agent-sandbox-proxy-route.service")
    firewall_invocation = unit("InvocationID", "agent-sandbox-proxy-firewall.service")

    proxy.succeed("systemctl restart agent-sandbox-policy.service")
    proxy.wait_for_unit("agent-sandbox-policy.service")
    keepalive_request("after-restart")
    assert unit("MainPID", "agent-sandbox-proxy.service") == proxy_pid, "policyd restart restarted the proxy"

    policyd_pid = unit("MainPID", "agent-sandbox-policy.service")
    proxy.succeed("/run/booted-system/specialisation/changed-proxy/bin/switch-to-configuration test")
    proxy.wait_for_unit("agent-sandbox-policy.service")
    assert unit("MainPID", "agent-sandbox-policy.service") != policyd_pid
    assert unit("MainPID", "agent-sandbox-proxy.service") == proxy_pid, "switch restarted the proxy"
    assert unit("InvocationID", "agent-sandbox-proxy-route.service") == route_invocation, "switch re-ran the route"
    assert unit("InvocationID", "agent-sandbox-proxy-firewall.service") == firewall_invocation, "switch restarted the firewall"
    keepalive_request("after-switch")
    sandbox_shell(proxy, "sandbox-proxy-bash", "curl --fail --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed | grep -q allowed-get", wrapper=session_wrapper)
    sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "http://169.254.100.1:8008/unlisted", wrapper=session_wrapper, expect_success=False)

  '';
})
