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

  # Sandboxed client for the freeze scenarios. Every mode triggers one
  # approval prompt from inside its own sandbox (curl to an unlisted URL),
  # which freezes the whole scope until the host approves it.
  freezeClient = pkgs.writeText "freeze-client.py" ''
    import hashlib
    import http.client
    import os
    import socket
    import ssl
    import subprocess
    import sys
    import time

    ORIGIN = "169.254.100.1"
    TLS_REQUEST = b"GET /allowed HTTP/1.1\r\nHost: 169.254.100.1:8443\r\nConnection: close\r\n\r\n"


    def freeze():
        done = subprocess.run(
            ["curl", "--silent", "--show-error", "--max-time", "120", "http://%s:8008/unlisted" % ORIGIN],
            capture_output=True,
            check=True,
        )
        assert done.stdout == b"unlisted-get\n", done.stdout


    def tls(split):
        context = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        session = context.wrap_bio(incoming, outgoing, server_hostname=ORIGIN)
        sock = socket.create_connection((ORIGIN, 8443), timeout=120)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def flush():
            data = outgoing.read()
            if data:
                sock.sendall(data)

        def run(step):
            while True:
                try:
                    result = step()
                except ssl.SSLWantReadError:
                    flush()
                    chunk = sock.recv(65536)
                    if not chunk:
                        raise EOFError("connection closed")
                    incoming.write(chunk)
                    continue
                flush()
                return result

        try:
            session.do_handshake()
        except ssl.SSLWantReadError:
            pass
        hello = outgoing.read()
        cut = 2 if split else 0
        sock.sendall(hello[:cut])
        freeze()
        sock.sendall(hello[cut:])
        run(session.do_handshake)
        run(lambda: session.write(TLS_REQUEST))
        response = b""
        while not response.endswith(b"allowed-get\n"):
            response += run(lambda: session.read(65536))
        assert response.startswith(b"HTTP/1.1 200"), response
        print("tls-ok", flush=True)


    def keepalive():
        conn = http.client.HTTPConnection(ORIGIN, 8008, timeout=120)

        def get():
            conn.request("GET", "/allowed")
            response = conn.getresponse()
            assert response.status == 200 and response.read() == b"allowed-get\n"

        get()
        port = conn.sock.getsockname()[1]
        freeze()
        get()
        assert conn.sock is not None and conn.sock.getsockname()[1] == port
        print("keepalive-ok port=%d" % port, flush=True)


    def download():
        conn = http.client.HTTPConnection(ORIGIN, 8009, timeout=300)
        conn.request("GET", "/big")
        response = conn.getresponse()
        assert response.status == 200, response.status
        digest = hashlib.sha256()
        size = 0
        frozen = False
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if not frozen and size >= 2 << 20:
                frozen = True
                freeze()
        print("download-ok size=%d sha=%s" % (size, digest.hexdigest()), flush=True)


    def closed():
        socket.create_connection((ORIGIN, 18085), timeout=10).close()
        time.sleep(8)
        print("closed-ok", flush=True)


    {
        "tls-whole": lambda: tls(False),
        "tls-split": lambda: tls(True),
        "keepalive": keepalive,
        "download": download,
        "closed": closed,
    }[sys.argv[1]]()
  '';

  # Streams 64 MiB at about 10 MiB/s and gives up when one send blocks for
  # more than 10 s, as an origin with a send timeout would.
  readaheadOrigin = pkgs.writeText "readahead-origin.py" ''
    import hashlib
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    BLOCKS = 64


    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path != "/big":
                self.send_error(404)
                return
            self.connection.settimeout(10)
            self.send_response(200)
            self.send_header("Content-Length", str(BLOCKS << 20))
            self.end_headers()
            digest = hashlib.sha256()
            try:
                for index in range(BLOCKS):
                    block = hashlib.sha256(str(index).encode()).digest() * 32768
                    digest.update(block)
                    self.wfile.write(block)
                    time.sleep(0.1)
                result = "completed " + digest.hexdigest()
            except OSError as error:
                result = "aborted " + type(error).__name__
            with open("/tmp/readahead-origin.result", "w") as handle:
                handle.write(result + "\n")
            self.close_connection = True


    ThreadingHTTPServer(("0.0.0.0", 8009), Handler).serve_forever()
  '';
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-approval-freeze";
  node.specialArgs = { inherit inputs; };

  nodes.approval =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate
      (httpServers [
        { port = 8008; }
        {
          certificate = "${tlsFixture}/server-cert.pem";
          port = 8443;
          privateKey = "${tlsFixture}/server-key.pem";
          serviceName = "https";
        }
      ])
      {
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

              declarativeAllow = [
                {
                  methods = [ "GET" ];
                  url = "http://169.254.100.1:8008/allowed";
                }
                {
                  methods = [ "GET" ];
                  url = "http://169.254.100.1:8009/big";
                }
                {
                  methods = [ "GET" ];
                  url = "https://169.254.100.1:8443/allowed";
                }
              ];
            };
          };

          packages = [
            (mkBash "sandbox-approve-bash" {
              extraPkgs = commonExtraPkgs ++ [
                pkgs.curl
                pkgs.python3
              ];
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
          8009
          8443
          18084
          18085
        ];

        systemd.services = {
          agent-sandbox-vm-readahead-origin = {
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = "${pkgs.python3}/bin/python ${readaheadOrigin}";
              Restart = "on-failure";
              User = "sandbox";
            };
          };

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

    def package_cmd(package, script, *, background=False, out="/tmp/approve-bg.out"):
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
                f"sh -c {shlex.quote(inner)} </dev/null >{out} 2>&1 &"
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

    # Freezes started from inside one sandbox launch: the client connects or
    # streams first, then runs curl against an unlisted URL, which prompts
    # and freezes the whole scope. The host holds the prompt for the stated
    # time and approves it.
    approval.wait_for_open_port(8009)
    approval.wait_for_open_port(8443)
    approval.succeed(
        command(
            "sh", "-c",
            "nohup sh -c 'while :; do runuser -u sandbox -- agent-sandbox-approve pending >> /tmp/pending-poll.log 2>&1; sleep 0.2; done' "
            "</dev/null >/dev/null 2>&1 &",
        )
    )

    def scope_of(mode):
        pattern = shlex.quote(f"^[^ ]*python[0-9.]* [^ ]*freeze-client\\.py {mode}$")
        return (
            f"pid=$(pgrep -f {pattern} | head -1); "
            "scope=$(awk -F: '$1 == 0 {print $3}' /proc/$pid/cgroup); "
            "dir=/sys/fs/cgroup$scope"
        )

    def frozen_usec(mode):
        return int(
            approval.succeed(
                scope_of(mode) + "; awk '$1 == \"frozen_usec\" {print $2}' $dir/cgroup.stat.local"
            ).strip()
        )

    def launch(mode):
        approval.succeed(": > /tmp/pending-poll.log")
        approval.succeed(
            package_cmd(
                "sandbox-approve-bash",
                f"python3 ${freezeClient} {mode}",
                background=True,
                out=f"/tmp/freeze-{mode}.out",
            )
        )

    def freeze_for(mode, seconds):
        approval.wait_until_succeeds(
            "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/unlisted'",
            timeout=60,
        )
        approval.wait_until_succeeds(scope_of(mode) + '; test "$(cat $dir/cgroup.freeze)" = 1', timeout=60)
        before = frozen_usec(mode)
        approval.succeed(f"sleep {seconds}")
        during = frozen_usec(mode)
        assert during - before >= (seconds - 1) * 1_000_000, (before, during)
        trigger_id = approval.succeed(
            "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"http\" && $5 ~ /unlisted/ {print $1; exit}'"
        ).strip()
        assert trigger_id, "trigger prompt vanished"
        approval.succeed(f"runuser -u sandbox -- agent-sandbox-approve approve {trigger_id} once")

    def finish(mode, marker):
        out = f"/tmp/freeze-{mode}.out"
        approval.wait_until_succeeds(f"grep -q -e {marker} -e Traceback {out}", timeout=120)
        result = approval.succeed(f"cat {out}")
        assert marker in result, result
        return result

    # ClientHello after a freeze: the TLS client connects, the scope is
    # frozen for longer than the 500 ms peek deadline, and only then does
    # the handshake start. The peek must not count the frozen time, so the
    # connection is inspected as HTTPS and never prompts as tcp://.
    launch("tls-whole")
    freeze_for("tls-whole", 4)
    finish("tls-whole", "tls-ok")
    approval.succeed("! grep -F -q 169.254.100.1:8443 /tmp/pending-poll.log")

    # The first two bytes of the TLS record header arrive before the
    # freeze and the rest after it: the second peek phase must also ignore
    # the frozen time.
    launch("tls-split")
    freeze_for("tls-split", 4)
    finish("tls-split", "tls-ok")
    approval.succeed("! grep -F -q 169.254.100.1:8443 /tmp/pending-poll.log")

    # A connection closed before any byte has nothing to route: no prompt,
    # and the scope is never frozen.
    launch("closed")
    approval.wait_until_succeeds(scope_of("closed") + "; test -r $dir/cgroup.stat.local", timeout=60)
    closed_before = frozen_usec("closed")
    approval.succeed("sleep 3")
    approval.succeed("! grep -F -q 169.254.100.1:18085 /tmp/pending-poll.log")
    assert frozen_usec("closed") == closed_before, closed_before
    finish("closed", "closed-ok")

    # HTTP/1 keep-alive across a freeze longer than the old 30 s header
    # read timeout: the second request reuses the same client connection.
    launch("keepalive")
    freeze_for("keepalive", 40)
    finish("keepalive", "keepalive-ok")

    # Upstream read-ahead: the origin aborts a transfer whose send blocks
    # for 10 s. The scope is frozen for 30 s mid-download, so only a proxy
    # that keeps reading the origin lets the transfer complete.
    approval.succeed("rm -f /tmp/readahead-origin.result")
    launch("download")
    freeze_for("download", 30)
    result = finish("download", "download-ok")
    approval.wait_until_succeeds("test -s /tmp/readahead-origin.result", timeout=120)
    origin = approval.succeed("cat /tmp/readahead-origin.result").strip()
    digest = result.split("sha=")[1].split()[0]
    assert origin == f"completed {digest}", (origin, result)
    assert f"size={64 << 20}" in result, result
  '';
})
