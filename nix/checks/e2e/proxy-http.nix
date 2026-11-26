{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e) proxyNode tlsFixture;
  boot = ''
    start_all()
    session_wrapper = (
        "env",
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    )

    for node in [proxy]:
        node.wait_for_unit("multi-user.target")
  '';
  # A system update that changes policyd and every proxy unit.
  changedProxy = {
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
  e2e = import ./common.nix {
    inherit inputs lib pkgs;
  };
  helpers = ''
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
  '';
  keepaliveScenarios = ''
    proxy.wait_for_unit("user@1000.service")
    proxy.wait_for_open_port(8008)
    proxy.wait_for_open_port(8080)
    proxy.wait_for_open_port(8443)
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
  parts = {
    conncap = {
      plain = true;

      script = ''
        # One sandbox opens 300 connections and leaves each with an unfinished
        # request head. The proxy admits 256 per sandbox and refuses the rest;
        # a second sandbox is unaffected while the first holds its slots.
        holder = (
            "fds=(); "
            "for i in $(seq 1 300); do "
            "exec {fd}<>/dev/tcp/169.254.100.1/8009 || break; "
            "printf 'GET /leading HTTP/1.1\\r\\nHost: 169.254.100.1:8009\\r\\n' >&$fd; "
            "fds+=($fd); done; "
            "echo opened=''${#fds[@]} > /tmp/conncap.opened; "
            "sleep 6; closed=0; "
            "for fd in \"''${fds[@]}\"; do "
            "read -t 0.05 -n 1 -u $fd _ 2>/dev/null; rc=$?; "
            "if [ $rc -eq 1 ]; then closed=$((closed + 1)); fi; done; "
            "echo closed=$closed > /tmp/conncap.result; "
            "sleep 12"
        )
        launch = command("runuser", "-u", "sandbox", "--", *session_wrapper, "sandbox-proxy-bash", "-c", holder)
        proxy.succeed(command("setsid", "-f", "sh", "-c", "exec " + launch + " </dev/null >/tmp/conncap.out 2>&1") + " </dev/null >/dev/null 2>&1")
        proxy.wait_until_succeeds("grep -q opened=300 /tmp/conncap.opened", timeout=60)

        # Another sandbox still gets through while the first sits at its cap.
        out = plain_curl("http://169.254.100.1:8009/leading")
        assert out.strip() == "a", f"another sandbox was refused: {out!r}"

        proxy.wait_until_succeeds("test -s /tmp/conncap.result", timeout=60)
        result = proxy.succeed("cat /tmp/conncap.result").strip()
        assert result == "closed=44", result
        # The refusals are logged once, not once per connection.
        refusals = proxy.succeed(
            "journalctl --no-pager -b -u agent-sandbox-proxy.service | grep -c 'concurrent connection cap' || true"
        ).strip()
        assert refusals == "1", f"expected one refusal log line, got {refusals}"

        # The holder's exit frees its slots.
        proxy.wait_until_succeeds("! pgrep -f 'dev/tcp/169.254.100.1/800[9]'", timeout=60)
        out = plain_curl("http://169.254.100.1:8009/leading")
        assert out.strip() == "a", f"slots were not freed: {out!r}"
      '';
    };

    dial = {
      plain = true;

      script = ''
        # Plain HTTP is dialed at an address the checked host maps to, not at the
        # IP the client chose. The client names plain-a.test but connects to
        # origin b; the proxy resolves the name (to origin a) and dials that.
        out = plain_curl("--connect-to plain-a.test:8009:169.254.100.50:8009 http://plain-a.test:8009/dial")
        assert out.strip() == "a", f"plain-a.test request reached {out!r}, not origin a"
        proxy.succeed("grep -Fx 'GET /dial plain-a.test:8009' /var/log/plain-origin-a.log")
        proxy.succeed("test ! -s /var/log/plain-origin-b.log")

        # A host that does not resolve is denied instead of dialed at the client's IP.
        plain_curl("--connect-to plain-nx.test:8009:169.254.100.50:8009 http://plain-nx.test:8009/dial", expect_success=False)
        proxy.succeed("test ! -s /var/log/plain-origin-b.log")
        proxy.succeed("! grep -q plain-nx /var/log/plain-origin-a.log")

        # The proxy resolves through the sandbox's DNS path. plain-a.test is in no
        # hosts file and only the DNS upstream behind the forwarder knows it, so
        # the dial above can only have worked through that path. The forwarder
        # cached the proxy's lookup, and the proxy sees the sandbox's nsswitch
        # and no nscd socket.
        proxy.succeed("grep -F 'query[A] plain-a.test' /var/log/plain-dns.log")
        proxy.succeed("${pkgs.jq}/bin/jq -e '.entries[\"169.254.100.1\"][] | select(.host == \"plain-a.test\")' /run/agent-sandbox/dns-cache.json")
        # Read inside the proxy's mount namespace: /proc/<pid>/root would follow
        # the /etc/static symlinks in the host's.
        proxy.succeed(
            "pid=$(systemctl show --property=MainPID --value agent-sandbox-proxy.service); "
            "in_proxy() { ${pkgs.util-linux}/bin/nsenter --mount --target $pid -- \"$@\"; }; "
            "in_proxy ${pkgs.coreutils}/bin/test ! -e /run/nscd/socket && "
            "in_proxy ${pkgs.coreutils}/bin/cat /etc/nsswitch.conf | grep -Fx 'hosts: files dns' && "
            "in_proxy ${pkgs.coreutils}/bin/cat /etc/resolv.conf | grep -Fx 'nameserver 169.254.100.1'"
        )

        # The hosts file is honoured ahead of DNS, as in the sandbox: plain-h.test
        # is in the host's hosts file only and never reaches the DNS upstream.
        out = plain_curl("--connect-to plain-h.test:8009:169.254.100.50:8009 http://plain-h.test:8009/dial")
        assert out.strip() == "a", f"plain-h.test request reached {out!r}, not origin a"
        proxy.succeed("! grep -q plain-h /var/log/plain-dns.log")
        proxy.succeed("test ! -s /var/log/plain-origin-b.log")
      '';
    };

    halfclose = {
      plain = true;

      script = ''
        # A client that shuts down its write side right after a complete
        # request still gets the response: socat half-closes the socket when
        # its input ends and waits for the answer.
        out = sandbox_shell(
            proxy,
            "sandbox-proxy-bash",
            "printf 'GET /leading HTTP/1.1\\r\\nHost: 169.254.100.1:8009\\r\\n\\r\\n' | socat -t 10 -T 30 - TCP4:169.254.100.1:8009",
            wrapper=session_wrapper,
        )
        assert out.startswith("HTTP/1.1 200"), f"half-closed request got {out!r}"
        assert out.rstrip().endswith("a"), f"origin a did not answer: {out!r}"
        proxy.succeed("grep -Fx 'GET /leading 169.254.100.1:8009' /var/log/plain-origin-a.log")
      '';
    };

    keepalive = {
      script = keepaliveScenarios;

      switch = true;
    };

    leading-crlf = {
      plain = true;

      script = ''
        # Empty lines before the request line (RFC 9112 section 2.2) still select
        # the HTTP path.
        def raw_request(prefix):
            script = (
                "exec 4<>/dev/tcp/169.254.100.1/8009; "
                f"printf '{prefix}GET /leading HTTP/1.1\\r\\nHost: 169.254.100.1:8009\\r\\nConnection: close\\r\\n\\r\\n' >&4; "
                "timeout 15 cat <&4; true"
            )
            return sandbox_shell(proxy, "sandbox-proxy-bash", script, wrapper=session_wrapper)

        control = raw_request("")
        assert control.startswith("HTTP/1.1 200"), f"request without empty lines: {control!r}"
        for prefix in ["\\r\\n", "\\r\\n\\r\\n", "\\n"]:
            raw = raw_request(prefix)
            assert raw.startswith("HTTP/1.1 200"), f"no HTTP response with prefix {prefix!r}: {raw!r}"
            assert raw.rstrip().endswith("a"), f"origin a did not answer with prefix {prefix!r}: {raw!r}"
        proxy.succeed("grep -Fx 'GET /leading 169.254.100.1:8009' /var/log/plain-origin-a.log")
      '';
    };

    methods = {
      plain = true;

      script = ''
        # Extension methods are recognised as HTTP and judged by policy. Raw TCP to
        # this port is not allowed, so an answer proves the HTTP proxy path, and the
        # origin sees the method and path of the proxied request.
        for method in ["PROPFIND", "MKCOL", "REPORT"]:
            out = plain_curl(f"-X {method} http://169.254.100.1:8009/dav/collection")
            assert out.strip() == "a", f"{method} answered {out!r}"
            proxy.succeed(f"grep -Fx '{method} /dav/collection 169.254.100.1:8009' /var/log/plain-origin-a.log")
      '';
    };

    policy.script = policyScenarios;

    startup.script = startupScenarios;
  };
  plainOrigin = address: label: extra: {
    after = [ "agent-sandbox-netns.service" ];
    requires = [ "agent-sandbox-netns.service" ];

    serviceConfig = {
      ExecStart = lib.escapeShellArgs [
        "${pkgs.python3}/bin/python"
        plainOriginScript
        address
        "8009"
        label
        "/var/log/plain-origin-${label}.log"
      ];

      Restart = "on-failure";
    }
    // extra;

    wantedBy = [ "multi-user.target" ];
  };
  # Plain HTTP origin that records "METHOD TARGET HOST" per request and
  # answers 200 with its label, for any method it is given.
  plainOriginScript = pkgs.writeText "agent-sandbox-vm-plain-origin.py" ''
    import sys
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    address, port, label, log = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    open(log, "a").close()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle_any(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            with open(log, "a") as out:
                out.write(f"{self.command} {self.path} {self.headers.get('Host')}\n")
            body = (label + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    for method in ["GET", "PROPFIND", "MKCOL", "REPORT"]:
        setattr(Handler, "do_" + method, Handler.handle_any)

    ThreadingHTTPServer((address, port), Handler).serve_forever()
  '';
  # Two plain HTTP origins on port 8009. Origin a listens on the host's
  # loopback, where traffic to 169.254.100.1 lands; origin b listens on a
  # second host-side address. plain-a.test is answered by the DNS the sandbox
  # uses and is in no hosts file; plain-h.test is in the host's hosts file
  # only; plain-nx.test resolves nowhere.
  plainOrigins = {
    agent-sandbox.network.httpProxy = {
      declarativeAllow = [
        {
          methods = [ "GET" ];
          url = "http://plain-a.test:8009/dial";
        }
        {
          methods = [ "GET" ];
          url = "http://plain-nx.test:8009/dial";
        }
        {
          methods = [ "GET" ];
          url = "http://plain-h.test:8009/dial";
        }
        {
          methods = [
            "GET"
            "PROPFIND"
            "MKCOL"
            "REPORT"
          ];

          url = "http://169.254.100.1:8009/dav/collection";
        }
        {
          methods = [ "GET" ];
          url = "http://169.254.100.1:8009/leading";
        }
      ];

      upstreamAllowCidrs = [ "169.254.100.50/32" ];
    };

    networking = {
      firewall.interfaces.asbx-test-host.allowedTCPPorts = [ 8009 ];
      hosts."169.254.100.1" = [ "plain-h.test" ];
    };

    systemd.services = {
      # The DNS upstream behind the forwarder answers plain-a.test and logs
      # every query it receives, so the scenario can tell which resolver the
      # proxy used.
      agent-sandbox-vm-dns.serviceConfig.ExecStart = lib.mkForce (
        lib.escapeShellArgs [
          "${pkgs.dnsmasq}/bin/dnsmasq"
          "--keep-in-foreground"
          "--no-resolv"
          "--no-hosts"
          "--bind-interfaces"
          "--listen-address=169.254.100.1"
          "--port=5353"
          "--user=sandbox"
          "--address=/plain-a.test/169.254.100.1"
          "--log-queries"
          "--log-facility=/var/log/plain-dns.log"
        ]
      );

      agent-sandbox-vm-plain-origin-a = plainOrigin "127.0.0.1" "a" { };

      agent-sandbox-vm-plain-origin-b = plainOrigin "169.254.100.50" "b" {
        ExecStartPre = "-${pkgs.iproute2}/bin/ip addr add 169.254.100.50/32 dev lo";
      };
    };
  };
  policyScenarios = ''
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
  '';
  proxyUnits = ''
    proxy.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
    proxy.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
    proxy.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
  '';
  # Preconditions a group establishes once: units up, sandbox user session
  # running.
  ready = ''
    ${helpers}
    ${boot}
    ${proxyUnits}
    proxy.wait_for_unit("user@1000.service")
  '';
  readyPlain = ''
    # Plain HTTP origins a and b, both on port 8009 and each logging every
    # request it receives. The sandbox reaches origin a at 169.254.100.1:8009,
    # which the host DNATs to its 127.0.0.1:8009; origin b listens on
    # 169.254.100.50.
    for label in ["a", "b"]:
        proxy.wait_for_unit(f"agent-sandbox-vm-plain-origin-{label}.service")
    proxy.wait_for_open_port(8009, "127.0.0.1")
    proxy.wait_for_open_port(8009, "169.254.100.50")

    def plain_curl(args, *, expect_success=True):
        return sandbox_shell(
            proxy,
            "sandbox-proxy-bash",
            "curl --noproxy '*' --fail --silent --show-error --max-time 30 " + args,
            wrapper=session_wrapper,
            expect_success=expect_success,
        )
  '';
  startupScenarios = ''
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
  '';
in
{
  # One VM check running the named parts' scenarios in order on one boot.
  # Parts must agree on `plain`, which changes the node; `switch` only adds
  # a specialisation that the keepalive part switches to at runtime, so a
  # part that needs it goes last.
  mkCheck =
    name: partNames:
    let
      selected = map (n: parts.${n}) partNames;
      has = flag: lib.any (p: p.${flag} or false) selected;
      plain = has "plain";
    in
    assert lib.assertMsg (lib.all (p: (p.plain or false) == plain) selected)
      "e2e-proxy-http-${name}: parts have different node configs";
    pkgs.testers.runNixOSTest (_: {
      name = "e2e-proxy-http-${name}";
      node.specialArgs = { inherit inputs; };

      nodes.proxy.imports = [
        proxyNode
      ]
      ++ lib.optional plain plainOrigins
      ++ lib.optional (has "switch") changedProxy;

      testScript = lib.concatStringsSep "\n" (
        [ ready ] ++ lib.optional plain readyPlain ++ map (p: p.script) selected
      );
    });
}
