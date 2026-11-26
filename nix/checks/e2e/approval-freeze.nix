{
  lib,
  pkgs,
  inputs,
}:
let
  inherit (e2e)
    baseNode
    commonExtraPkgs
    dnsService
    httpServers
    mkBash
    module
    tlsFixture
    ;
  e2e = import ./common.nix {
    inherit inputs lib pkgs;
  };
  # Sandboxed client for the freeze scenarios. Every mode triggers one
  # approval prompt from inside its own sandbox (curl to an unlisted URL),
  # which freezes the whole scope until the host approves it.
  freezeClient = pkgs.writeText "freeze-client.py" ''
    import hashlib
    import http.client
    import os
    import select
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


    def idle():
        # One connection idles between requests, the other sends a request
        # head that never ends. The sandbox is never frozen here. The proxy
        # closes the idle keep-alive connection gracefully after its 30 s
        # idle bound (an orderly FIN, no reset), and drops the partial head
        # once the 5 s grace ends.
        conn = http.client.HTTPConnection(ORIGIN, 8008, timeout=120)
        conn.request("GET", "/allowed")
        response = conn.getresponse()
        assert response.status == 200 and response.read() == b"allowed-get\n"
        idle_sock = conn.sock
        slow_sock = socket.create_connection((ORIGIN, 8008), timeout=120)
        slow_sock.sendall(("GET /allowed HTTP/1.1\r\nHost: %s:8008\r\n" % ORIGIN).encode())
        started = time.monotonic()
        closed = {}
        orderly = {}
        tick = 0
        while len(closed) < 2 and time.monotonic() - started < 120:
            tick += 1
            if "slow" not in closed and tick % 5 == 0:
                try:
                    slow_sock.sendall(b"X-Slow: 1\r\n")
                except OSError:
                    closed["slow"] = time.monotonic() - started
            for name, sock in (("idle", idle_sock), ("slow", slow_sock)):
                if name in closed or not select.select([sock], [], [], 0)[0]:
                    continue
                try:
                    data = sock.recv(4096)
                    orderly[name] = True
                except OSError:
                    data = b""
                    orderly[name] = False
                if not data:
                    closed[name] = time.monotonic() - started
            time.sleep(1)
        assert set(closed) == {"idle", "slow"}, closed
        assert 28 <= closed["idle"] < 34, closed
        assert orderly["idle"], "the idle connection was reset instead of closed gracefully"
        assert 33 <= closed["slow"] <= 50, closed
        print("idle-ok idle=%.1f slow=%.1f" % (closed["idle"], closed["slow"]), flush=True)


    def many():
        # Eight concurrent downloads, then a freeze: the proxy reads ahead
        # for all of them, within the sandbox's share of the budget. The
        # origin gives up on a download after 10 s of blocked sends, and a
        # TCP sender whose receiver stalled that long can sit in
        # retransmission backoff for minutes after the receiver resumes, so
        # the scenario measures the proxy while frozen and then abandons the
        # downloads instead of draining them.
        bodies = []
        for _ in range(8):
            conn = http.client.HTTPConnection(ORIGIN, 8009, timeout=300)
            conn.request("GET", "/big")
            response = conn.getresponse()
            assert response.status == 200, response.status
            response.read(2 << 20)
            bodies.append(conn)
        freeze()
        for conn in bodies:
            conn.close()
        check = http.client.HTTPConnection(ORIGIN, 8008, timeout=60)
        check.request("GET", "/allowed")
        answer = check.getresponse()
        assert answer.status == 200 and answer.read() == b"allowed-get\n"
        print("many-ok", flush=True)


    {
        "tls-whole": lambda: tls(False),
        "tls-split": lambda: tls(True),
        "keepalive": keepalive,
        "idle": idle,
        "many": many,
        "download": download,
        "closed": closed,
    }[sys.argv[1]]()
  '';
  node =
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

                upstreamAllowCidrs = [ "169.254.100.1/32" ];
              };
            };

            packages = [
              (mkBash "sandbox-approve-bash" {
                extraPkgs = commonExtraPkgs ++ [
                  pkgs.curl
                  pkgs.python3
                ];
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
            agent-sandbox-vm-dns = dnsService;

            agent-sandbox-vm-readahead-origin = {
              wantedBy = [ "multi-user.target" ];

              serviceConfig = {
                ExecStart = "${pkgs.python3}/bin/python ${readaheadOrigin}";
                Restart = "on-failure";
                User = "sandbox";
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
  scenarios = {
    download = ''
      # Upstream read-ahead: the origin aborts a transfer whose send blocks
      # for 10 s. The scope is frozen for 30 s mid-download, so only a proxy
      # that keeps reading the origin lets the transfer complete.
      # Downloads abandoned by an earlier scenario may still be aborting at
      # the origin and write the shared result file; wait them out and clear it.
      approval.wait_until_succeeds("test -z \"$(ss -Htn state established '( sport = :8009 )')\"", timeout=120)
      approval.succeed("sleep 2; rm -f /tmp/readahead-origin.result")
      launch("download")
      freeze_for("download", 30)
      result = finish("download", "download-ok")
      approval.wait_until_succeeds("test -s /tmp/readahead-origin.result", timeout=120)
      origin = approval.succeed("cat /tmp/readahead-origin.result").strip()
      digest = result.split("sha=")[1].split()[0]
      assert origin == f"completed {digest}", (origin, result)
      assert f"size={64 << 20}" in result, result
    '';

    idle = ''
      # The proxy bounds a connection that waits for a request head, idle
      # between requests or part-way through a head, to 30 s of unfrozen time.
      # An unfrozen sandbox's idle keep-alive connection and its slowloris
      # head are both closed: the keep-alive connection gracefully after about
      # 30 s, the partial head after the 5 s grace.
      launch("idle")
      finish("idle", "idle-ok")
    '';

    keepalive = ''
      # HTTP/1 keep-alive across a freeze longer than the old 30 s header
      # read timeout: the second request reuses the same client connection.
      launch("keepalive")
      freeze_for("keepalive", 40)
      finish("keepalive", "keepalive-ok")
    '';

    many = ''
      # Read-ahead is a hard cap with a per-sandbox share: eight concurrent
      # downloads of one frozen sandbox may not grow the proxy by more than
      # that sandbox's half of the 128 MiB budget plus a margin. Without the
      # share the proxy would buffer the whole budget.
      baseline_kib = proxy_rss_peak_kib(1)
      rss_peak = []
      launch("many")
      freeze_for("many", 30, rss_peak)
      finish("many", "many-ok")
      growth_mib = (rss_peak[0] - baseline_kib) / 1024
      print(f"proxy RSS grew {growth_mib:.1f} MiB during the frozen downloads")
      assert growth_mib < 64 + 32, growth_mib
    '';

    # Passthrough and prompt-time freezes triggered from one-shot commands.
    prompt = ''
      # Raw TCP passthrough: non-HTTP bytes on an unusual port take the
      # checked splice instead of the HTTP path. Port 18084 has a
      # declarative rule, so this completes with no prompt at all.
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

      # A client that shut down its write side after its request (socat does
      # when its input ends) is half-closed, not gone: the prompt stays up
      # and the answer arrives once it is approved. The proxy tells this from
      # a full close by the client's socket, which keeps its inode in the
      # socket table the unprivileged proxy user can read.
      approval.succeed("rm -f /tmp/halfclose.out")
      approval.succeed(
          package_cmd(
              "sandbox-approve-bash",
              "printf 'GET /unlisted HTTP/1.1\\r\\nHost: 169.254.100.1:8008\\r\\nConnection: close\\r\\n\\r\\n' | socat -t 120 -T 120 - TCP4:169.254.100.1:8008",
              background=True,
              out="/tmp/halfclose.out",
          )
      )
      approval.wait_until_succeeds(
          "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/unlisted'"
      )
      approval.succeed("sleep 8")
      approval.succeed(
          "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/unlisted'"
      )
      owned = approval.succeed(
          "ip netns exec agent-sandbox runuser -u agent-sandbox-proxy -- ss -tnie state fin-wait-2 dst 169.254.100.1:8008"
      )
      assert [token for token in owned.split() if token.startswith("ino:") and token != "ino:0"], owned
      half_id = approval.succeed(
          "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"http\" && $5 ~ /unlisted/ {print $1; exit}'"
      ).strip()
      approval.succeed(f"runuser -u sandbox -- agent-sandbox-approve approve {half_id} once")
      approval.wait_until_succeeds("grep -q unlisted-get /tmp/halfclose.out", timeout=60)

      # A client that gives up closes its socket completely (a FIN, no reset
      # when no data is left unread): killing the process stands in for a
      # timeout or a killed tool. The pending prompt is withdrawn, so an
      # approval can no longer send the request upstream.
      approval.succeed(
          package_cmd(
              "sandbox-approve-bash",
              "curl --silent --max-time 120 -X POST --data x http://169.254.100.1:8008/unlisted-abandon",
              background=True,
              out="/tmp/abandon.out",
          )
      )
      approval.wait_until_succeeds(
          "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'unlisted-abandon'"
      )
      approval.succeed("pkill -KILL -f '^[^ ]*curl .*unlisted-abandon'")
      approval.wait_until_succeeds(
          "! runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'unlisted-abandon'",
          timeout=30,
      )
    '';

    tls = ''
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
    '';
  };
  setup = ''
    import shlex

    def command(*args):
        return shlex.join(str(arg) for arg in args)

    start_all()
    approval.wait_for_unit("multi-user.target")
    approval.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
    approval.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
    approval.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
    approval.wait_for_unit("agent-sandbox-policy.service")
    approval.wait_for_unit("agent-sandbox-vm-tcp-18084.service")
    approval.wait_for_unit("agent-sandbox-vm-tcp-18085.service")
    approval.wait_for_open_port(8008)
    approval.wait_for_open_port(8009)
    approval.wait_for_open_port(8443)

    approve_env = ["env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"]

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

    # Freezes started from inside one sandbox launch: the client connects or
    # streams first, then runs curl against an unlisted URL, which prompts
    # and freezes the whole scope. The host holds the prompt for the stated
    # time and approves it.
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

    def proxy_rss_peak_kib(seconds):
        # Peak resident set of the proxy over `seconds`, sampled every second.
        return int(
            approval.succeed(
                "pid=$(systemctl show --property MainPID --value agent-sandbox-proxy.service); "
                f"max=0; end=$((SECONDS + {seconds})); "
                "while [ $SECONDS -lt $end ]; do "
                "rss=$(awk '$1 == \"VmRSS:\" {print $2}' /proc/$pid/status); "
                "[ \"$rss\" -gt \"$max\" ] && max=$rss; sleep 1; done; echo $max"
            ).strip()
        )

    def freeze_for(mode, seconds, rss_peak=None):
        approval.wait_until_succeeds(
            "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/unlisted'",
            timeout=60,
        )
        approval.wait_until_succeeds(scope_of(mode) + '; test "$(cat $dir/cgroup.freeze)" = 1', timeout=60)
        before = frozen_usec(mode)
        if rss_peak is None:
            approval.succeed(f"sleep {seconds}")
        else:
            rss_peak.append(proxy_rss_peak_kib(seconds))
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
  '';
in
{
  # The check `name` boots one VM, runs setup once, then each part's
  # scenario in the order given.
  mkCheck =
    name: parts:
    pkgs.testers.runNixOSTest (_: {
      name = "e2e-approval-freeze-${name}";
      node.specialArgs = { inherit inputs; };
      nodes.approval = node;
      testScript = setup + lib.concatMapStrings (part: scenarios.${part}) parts;
    });
}
