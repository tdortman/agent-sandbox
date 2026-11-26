# Builder for the e2e-dns-attribution-* checks: one node, a scripted DNS
# upstream behind the forwarder, and the helpers every part shares.
{
  lib,
  pkgs,
  inputs,
}:
let
  inherit (e2e)
    baseNode
    commonExtraPkgs
    mkBash
    module
    tlsFixture
    ;
  # One DNS-over-TCP A query through the forwarder, printing the response
  # code and the answered address.
  dnsTcpQuery = pkgs.writeScriptBin "dns-tcp-query" ''
    #!${pkgs.python3}/bin/python3
    import socket
    import struct
    import sys

    name = sys.argv[1]
    labels = [bytes([len(label)]) + label.encode() for label in name.split(".")]
    question = b"".join(labels) + b"\x00"
    header = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
    query = header + question + struct.pack("!HH", 1, 1)


    def read_exact(sock, count):
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise SystemExit("short dns reply")
            data += chunk
        return data


    with socket.create_connection(("169.254.100.1", 53), timeout=10) as sock:
        sock.sendall(struct.pack("!H", len(query)) + query)
        size = struct.unpack("!H", read_exact(sock, 2))[0]
        response = read_exact(sock, size)

    rcode = response[3] & 0xF
    answers = struct.unpack("!H", response[6:8])[0]
    address = socket.inet_ntoa(response[-4:]) if answers else "none"
    print(f"rcode={rcode} address={address}")
  '';
  # One DNS-over-UDP A query per name argument, through the forwarder. Labels
  # are sent as given, so a name can carry bytes no resolver library would
  # put in a query. Prints each name with its response code.
  dnsUdpQuery = pkgs.writeScriptBin "dns-udp-query" ''
    #!${pkgs.python3}/bin/python3
    import socket
    import struct
    import sys

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10)
        for name in sys.argv[1:]:
            labels = [bytes([len(label)]) + label.encode() for label in name.split(".")]
            question = b"".join(labels) + b"\x00"
            header = struct.pack("!HHHHHH", 0x4343, 0x0100, 1, 0, 0, 0)
            sock.sendto(header + question + struct.pack("!HH", 1, 1), ("169.254.100.1", 53))
            response = sock.recv(4096)
            print(f"{name} rcode={response[3] & 0xF}")
  '';
  e2e = import ./common.nix {
    inherit inputs lib pkgs;
  };
  echoService = socatAddress: {
    serviceConfig = {
      ExecStart = "${pkgs.socat}/bin/socat ${socatAddress} EXEC:${pkgs.coreutils}/bin/cat";
      Restart = "on-failure";
      User = "sandbox";
    };

    wantedBy = [ "multi-user.target" ];
  };
  node = lib.recursiveUpdate baseNode {
    imports = [ module ];

    agent-sandbox = {
      enable = true;

      network = {
        enable = true;

        # Allowed destinations the second sandbox reaches while the first
        # sandbox's prompt is pending.
        declarativeAllow = [
          {
            host = "169.254.100.1";
            port = 18084;
          }
          {
            host = "169.254.100.1";
            port = 18086;
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
        (mkBash "dns-a-bash" { extraPkgs = sandboxTools; })
        (mkBash "dns-b-bash" { extraPkgs = sandboxTools; })
      ];

      # Pending requests are recorded but no UI is spawned; the scenario
      # answers them with agent-sandbox-approve.
      policy.uiBackend = "none";
    };

    networking.firewall.interfaces.asbx-test-host = {
      allowedTCPPorts = [ 18084 ];
      allowedUDPPorts = [ 18086 ];
    };

    systemd.services = {
      agent-sandbox-vm-dns-upstream = {
        after = [ "agent-sandbox-netns.service" ];
        requires = [ "agent-sandbox-netns.service" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 ${upstreamScript}";
          Restart = "on-failure";
        };
      };

      agent-sandbox-vm-tcp-18084 = echoService "TCP4-LISTEN:18084,fork,reuseaddr";
      agent-sandbox-vm-udp-18086 = echoService "UDP4-RECVFROM:18086,fork,reuseaddr";
    };

    virtualisation.cores = 4;
  };
  # Registers as the policy UI of one sandbox session and records every
  # prompt push policyd sends, without answering. The recorded pushes carry
  # the attribution aliases that `agent-sandbox-approve pending` omits, and
  # the registered UI session id is what session-scoped answers name.
  observerScript = pkgs.writeText "agent-sandbox-vm-ui-observer.py" ''
    import json
    import socket
    import sys

    session, log = sys.argv[1], sys.argv[2]
    sock = socket.socket(socket.AF_UNIX)
    sock.connect("/run/agent-sandbox/policy.sock")
    request = {
        "op": "register_ui",
        "ui_client": "e2e-observer",
        "ctx": {"sandbox_session_id": session},
    }
    sock.sendall((json.dumps(request) + "\n").encode())

    with sock.makefile("r") as stream, open(log, "a", buffering=1) as out:
        for line in stream:
            message = json.loads(line)
            if message.get("result") == "register_ui":
                out.write("registered " + message["session_id"] + "\n")
            elif message.get("type") != "heartbeat":
                out.write("push " + line)
  '';
  preamble = ''
    import json
    import shlex
    import time

    DECOY = "198.51.100.66"
    DECOY_TCP = "198.51.100.67"
    SHARED = "198.51.100.50"
    approve = "runuser -u sandbox -- agent-sandbox-approve"
    session_env = [
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    ]

    start_all()
    attribution.wait_for_unit("multi-user.target")
    attribution.wait_for_unit("agent-sandbox-dns.service", timeout=120)
    attribution.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
    attribution.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
    attribution.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
    attribution.wait_for_unit("agent-sandbox-policy.service")
    attribution.wait_for_unit("agent-sandbox-vm-dns-upstream.service")
    attribution.wait_for_unit("agent-sandbox-vm-tcp-18084.service")
    attribution.wait_for_unit("agent-sandbox-vm-udp-18086.service")
    attribution.wait_for_open_port(5353, "169.254.100.1")

    # Raw flows are judged per destination in the kernel verdict cache; the
    # shared-IP scenario below is only meaningful with the cache armed.
    attribution.succeed(
        "journalctl --no-pager -b -u agent-sandbox-nfq.service | grep -q 'verdict cache enabled'"
    )


    def sandbox_line(package, session, script):
        # The wrapper takes the session id from the environment, so the
        # scenario knows it before the sandbox starts.
        inner = f"cd /home/user && {shlex.join([package, '-c', script])}"
        return shlex.join([
            "runuser", "-u", "sandbox", "--", "env", *session_env,
            f"AGENT_SANDBOX_SESSION_ID={session}", "sh", "-c", inner,
        ])


    def run_sandbox(package, session, script):
        return attribution.succeed(sandbox_line(package, session, script), timeout=120)


    def start_sandbox(tag, package, session, script):
        # Detached, with the exit status recorded for later.
        inner = f"{sandbox_line(package, session, script)}; echo $? > /tmp/{tag}.status"
        attribution.succeed(shlex.join([
            "sh", "-c",
            f"nohup sh -c {shlex.quote(inner)} </dev/null >/tmp/{tag}.out 2>&1 &",
        ]))


    def exit_status(tag, timeout=60):
        attribution.wait_until_succeeds(f"test -s /tmp/{tag}.status", timeout=timeout)
        return int(attribution.succeed(f"cat /tmp/{tag}.status").strip())
    def denied(tag, destination, count=1, timeout=60):
        # A denied raw flow is closed by the proxy after the connection was
        # accepted, so the client exits cleanly; the proxy's denial is the
        # observable.
        exit_status(tag, timeout=timeout)
        attribution.wait_until_succeeds(
            "test \"$(journalctl --no-pager -b -u agent-sandbox-proxy.service "
            f"| grep -c -F 'denied by policy destination={destination}')\" -ge {count}",
            timeout=timeout,
        )



    def pending_rows():
        rows = []
        for line in attribution.succeed(f"{approve} pending").splitlines():
            fields = line.split("\t")
            if len(fields) >= 5 and fields[1] == "network":
                rows.append((fields[0], fields[4]))
        return rows


    def wait_pending(port, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            rows = [row for row in pending_rows() if row[1].endswith(f":{port}")]
            if rows:
                return rows[0]
            if time.monotonic() > deadline:
                raise Exception(f"no pending prompt on port {port}; pending: {pending_rows()}")
            time.sleep(1)


    def assert_no_pending(port, settle=4):
        # A flow's later datagrams can reach nfq after its sender has exited
        # and its first datagram was answered. Such a packet has no owner and
        # may not raise a prompt nobody can answer.
        time.sleep(settle)
        rows = [row for row in pending_rows() if row[1].endswith(f":{port}")]
        assert not rows, f"stale prompt left pending for port {port}: {rows}"


    def deny(prompt_id, *scope):
        attribution.succeed(f"{approve} deny {prompt_id} {shlex.join(scope)}")


    def start_observer(session):
        log = f"/tmp/ui-{session}.log"
        attribution.succeed(shlex.join([
            "sh", "-c",
            "nohup runuser -u sandbox -- ${pkgs.python3}/bin/python3 "
            f"${observerScript} {session} {log} </dev/null >/tmp/ui-{session}.err 2>&1 &",
        ]))
        attribution.wait_until_succeeds(f"grep -q '^registered ' {log}")
        return attribution.succeed(f"sed -n 's/^registered //p' {log}").strip()


    def wait_push(session, port, timeout=60):
        deadline = time.monotonic() + timeout
        while True:
            out = attribution.succeed(f"cat /tmp/ui-{session}.log")
            for line in out.splitlines():
                if not line.startswith("push "):
                    continue
                push = json.loads(line[len("push "):])
                if push.get("type") == "network_request" and push.get("port") == port:
                    return push
            if time.monotonic() > deadline:
                raise Exception(f"no UI push for port {port}:\n{out}")
            time.sleep(1)


    def raw_connect(port, address):
        return f"printf raw | socat -T 120 - TCP4:{address}:{port}"


    def raw_udp(port, address):
        # UDP to a port outside the HTTP/3 intercept set takes the nfq
        # transport check even in proxy mode, which is the path that names
        # shared IPs and publishes verdicts.
        return f"printf raw | socat -T 30 - UDP4:{address}:{port}"


    def udp_denied(tag, host, port, count=1, timeout=60):
        exit_status(tag, timeout=timeout)
        attribution.wait_until_succeeds(
            "test \"$(journalctl --no-pager -b -u agent-sandbox-nfq.service "
            f"| grep -F 'reject (policy)' | grep -F 'host={host} ' | grep -c -F 'port={port}')\" -ge {count}",
            timeout=timeout,
        )
  '';
  sandboxTools = commonExtraPkgs ++ [
    dnsTcpQuery
    dnsUdpQuery
    pkgs.getent
    pkgs.python3
  ];
  scenarios = {
    ambiguous = ''
      # A sandbox process that forks while holding an unconnected TCP socket
      # makes the socket's owner ambiguous. nfq rejects such a flow; the
      # reject must reach the client as a reset, once, and not send the packet
      # around the queueing chain again for as long as the ambiguity lasts.
      AMBIGUOUS_SCRIPT = (
          "import os, socket, time\n"
          "sock = socket.socket()\n"
          "sock.settimeout(15)\n"
          "child = os.fork()\n"
          "if child == 0:\n"
          "    time.sleep(60)\n"
          "    os._exit(0)\n"
          "start = time.monotonic()\n"
          "try:\n"
          "    sock.connect(('169.254.100.1', 18084))\n"
          "    outcome = 'connected'\n"
          "except ConnectionRefusedError:\n"
          "    outcome = 'refused'\n"
          "except OSError as error:\n"
          "    outcome = 'other ' + type(error).__name__\n"
          "print('outcome=' + outcome)\n"
          "print('elapsed=%d' % (time.monotonic() - start))\n"
          "os.kill(child, 9)\n"
          "os.waitpid(child, 0)\n"
      )
      answer = run_sandbox(
          "dns-a-bash", "dns-ambiguous",
          f"python3 -c {shlex.quote(AMBIGUOUS_SCRIPT)}",
      )
      assert "outcome=refused" in answer, answer
      elapsed = int(answer.split("elapsed=")[1].split()[0])
      assert elapsed < 5, f"ambiguous flow took {elapsed}s to fail: {answer}"
      rejects = int(attribution.succeed(
          "journalctl --no-pager -b -u agent-sandbox-nfq.service "
          "| grep -c -F 'rejecting ambiguous socket ownership' || true"
      ).strip())
      assert 1 <= rejects <= 3, f"nfq rejected the ambiguous flow {rejects} times"

      # With the second holder gone the same destination works again.
      answer = run_sandbox(
          "dns-a-bash", "dns-ambiguous-after",
          "printf tcp-ok | socat -T 5 - TCP4:169.254.100.1:18084",
      )
      assert "tcp-ok" in answer, answer
    '';

    cross = ''
      # One sandbox's resolutions do not change the name another sandbox's raw
      # prompt shows. The first sandbox is attributed to x-a.test by its first
      # flow; the second resolves x-b.test, the newest name for the address,
      # while the first waits. Each prompt names the sandbox's own resolution.
      CROSS = "198.51.100.95"
      start_observer("dns-cross-a")
      cross_a_script = (
          "dns-udp-query x-a.test; " + raw_udp(9403, CROSS)
          + "; sleep 30; " + raw_udp(9405, CROSS)
      )
      start_sandbox("cross-a", "dns-a-bash", "dns-cross-a", cross_a_script)
      prompt_id, destination = wait_pending(9403)
      assert destination == "x-a.test:9403", destination
      deny(prompt_id)

      start_sandbox(
          "cross-b", "dns-b-bash", "dns-cross-b",
          "dns-udp-query x-b.test; " + raw_udp(9404, CROSS),
      )
      prompt_id, destination = wait_pending(9404)
      assert destination == "x-b.test:9404", destination
      deny(prompt_id)
      udp_denied("cross-b", "x-b.test", 9404)

      prompt_id, destination = wait_pending(9405, timeout=90)
      assert destination == "x-a.test:9405", f"first sandbox's prompt named {destination!r}"
      push = wait_push("dns-cross-a", 9405)
      assert push["host"] == "x-a.test", push
      assert json.loads(push["url"].partition("#agent-sandbox-aliases=")[2]) == ["x-b.test"], push
      deny(prompt_id)
      udp_denied("cross-a", "x-a.test", 9405)
      assert_no_pending(9405)
    '';

    forged = ''
      # Forged upstream replies. The upstream sends a reply with a wrong
      # transaction ID and one with a wrong question, both mapping the name to
      # the decoy, before the real answer.
      answer = run_sandbox("dns-a-bash", "dns-forged", "getent ahostsv4 forged.test")
      assert "198.51.100.10" in answer, answer
      assert DECOY not in answer, answer
      attribution.succeed("grep -q '^forged-udp ' /var/log/dns-upstream.log")

      # The decoy was never attributed: a raw flow to it names the bare IP.
      start_sandbox("decoy", "dns-a-bash", "dns-forged-decoy", raw_connect(9101, DECOY))
      prompt_id, destination = wait_pending(9101)
      assert destination == f"{DECOY}:9101", f"decoy prompt named {destination!r}"
      deny(prompt_id)
      denied("decoy", f"{DECOY}:9101")

      # Positive control: the real answer is attributed to the queried name.
      start_sandbox("real", "dns-a-bash", "dns-forged-real", raw_connect(9102, "198.51.100.10"))
      prompt_id, destination = wait_pending(9102)
      assert destination == "forged.test:9102", f"real-IP prompt named {destination!r}"
      deny(prompt_id)
      denied("real", "198.51.100.10:9102")
    '';

    forged-tcp = ''
      # Over TCP the forwarder takes the first reply: a forged one fails the
      # lookup instead of reaching the client, and nothing is attributed.
      answer = run_sandbox("dns-a-bash", "dns-forged-tcp", "dns-tcp-query tcp-forged.test")
      assert "rcode=2 address=none" in answer, answer
      attribution.succeed("grep -q '^forged-tcp ' /var/log/dns-upstream.log")
      answer = run_sandbox("dns-a-bash", "dns-tcp-ok", "dns-tcp-query tcp-ok.test")
      assert "rcode=0 address=198.51.100.11" in answer, answer
      start_sandbox("decoy-tcp", "dns-a-bash", "dns-forged-decoy-tcp", raw_connect(9103, DECOY_TCP))
      prompt_id, destination = wait_pending(9103)
      assert destination == f"{DECOY_TCP}:9103", f"tcp decoy prompt named {destination!r}"
      deny(prompt_id)
      denied("decoy-tcp", f"{DECOY_TCP}:9103")
    '';

    hostile = ''
      # Hostile names. A sandbox can query names no resolver library sends and
      # an attacker-run zone answers them. None may reach the cache, a prompt,
      # the pending list or a daemon log; the valid names on the same address
      # still do.
      HOSTILE = "198.51.100.90"
      hostile_names = [
          "benign-h2.test", "benign-h.test", "evil?.test", "two words.test", "frag#x.test",
      ]
      start_observer("dns-hostile")
      hostile_script = (
          "dns-udp-query " + " ".join(shlex.quote(name) for name in hostile_names)
          + "; " + raw_udp(9401, HOSTILE)
      )
      start_sandbox("hostile", "dns-a-bash", "dns-hostile", hostile_script)
      prompt_id, destination = wait_pending(9401)
      assert destination == "benign-h.test:9401", f"hostile prompt named {destination!r}"
      push = wait_push("dns-hostile", 9401)
      base, marker, fragment = push["url"].partition("#agent-sandbox-aliases=")
      assert push["host"] == "benign-h.test", push
      assert base == f"udp://{HOSTILE}:9401", push
      assert marker and json.loads(fragment) == ["benign-h2.test"], push
      for name in hostile_names[2:]:
          attribution.succeed(
              f"grep -qF {shlex.quote('query ' + name)} /var/log/dns-upstream.log"
          )
      surfaces = attribution.succeed(
          f"{approve} pending; cat /tmp/ui-dns-hostile.log /run/agent-sandbox/dns-cache.json; "
          "journalctl --no-pager -b -u agent-sandbox-nfq.service -u agent-sandbox-dns.service "
          "-u agent-sandbox-policy.service"
      )
      for needle in ("evil?", "two words", "two\\032words", "frag#x"):
          assert needle not in surfaces, f"hostile name fragment {needle!r} reached a surface"
      deny(prompt_id)
      udp_denied("hostile", "benign-h.test", 9401)
    '';

    many = ''
      # Many names for one address. The cache file keeps 16 and a prompt shows
      # at most 8 other names.
      MANY = "198.51.100.91"
      many_names = [f"many-{index}.test" for index in range(60)]
      start_observer("dns-many")
      many_script = "dns-udp-query " + " ".join(many_names) + "; " + raw_udp(9402, MANY)
      start_sandbox("many", "dns-a-bash", "dns-many", many_script)
      prompt_id, destination = wait_pending(9402)
      assert destination == "many-59.test:9402", destination
      push = wait_push("dns-many", 9402)
      aliases = json.loads(push["url"].partition("#agent-sandbox-aliases=")[2])
      assert aliases == [f"many-{index}.test" for index in range(58, 50, -1)], aliases
      cached = int(attribution.succeed(
          f"${pkgs.jq}/bin/jq '.entries[\"{MANY}\"] | length' /run/agent-sandbox/dns-cache.json"
      ))
      assert cached == 16, f"cache file holds {cached} names for one address"
      deny(prompt_id)
      udp_denied("many", "many-59.test", 9402)
    '';

    rawtcp = ''
      # Raw TCP in proxy mode goes through the proxy, not the NFQUEUE transport
      # check. Its prompt still names the host the DNS cache gave the address
      # and lists the other names the address is known by. The sandbox also
      # resolves three names no hostname can be spelled as; none may appear.
      HOSTILE = "198.51.100.90"
      tcp_names = [
          "benign-h2.test", "benign-h.test", "evil?.test", "two words.test", "frag#x.test",
      ]
      start_observer("dns-rawtcp")
      rawtcp_script = (
          "dns-udp-query " + " ".join(shlex.quote(name) for name in tcp_names)
          + "; " + raw_connect(9501, HOSTILE)
      )
      start_sandbox("rawtcp", "dns-a-bash", "dns-rawtcp", rawtcp_script)
      prompt_id, destination = wait_pending(9501)
      assert destination == "benign-h.test:9501", f"raw TCP prompt named {destination!r}"
      push = wait_push("dns-rawtcp", 9501)
      base, marker, fragment = push["url"].partition("#agent-sandbox-aliases=")
      assert push["host"] == "benign-h.test", push
      assert push["scheme"] == "tcp", push
      assert marker and json.loads(fragment) == ["benign-h2.test"], f"alias fragment {fragment!r}: {push}"
      surfaces = attribution.succeed(
          f"{approve} pending; cat /tmp/ui-dns-rawtcp.log; "
          "journalctl --no-pager -b -u agent-sandbox-proxy.service -u agent-sandbox-policy.service"
      )
      for needle in ("evil?", "two words", "two\\032words", "frag#x"):
          assert needle not in surfaces, f"hostile name fragment {needle!r} reached a surface"
      deny(prompt_id)
      denied("rawtcp", f"{HOSTILE}:9501")
    '';

    sched = ''
      # NFQUEUE keeps judging other flows while one waits on a prompt. The
      # first sandbox holds an unlisted UDP flow pending; the second sandbox
      # resolves a name and opens allowed TCP and UDP flows meanwhile.
      start_sandbox(
          "sched-a", "dns-a-bash", "dns-sched-a",
          "printf pending | socat -T 120 - UDP4:198.51.100.77:9999",
      )
      held_id, destination = wait_pending(9999)
      assert destination == "198.51.100.77:9999", destination

      run_sandbox(
          "dns-b-bash", "dns-sched-b",
          "timeout 10 getent ahostsv4 probe.test | grep -q 198.51.100.200"
          " && printf tcp-ok | timeout 10 socat -T 5 - TCP4:169.254.100.1:18084 | grep -q tcp-ok"
          " && printf udp-ok | timeout 10 socat -T 5 - UDP4:169.254.100.1:18086 | grep -q udp-ok",
      )

      assert (held_id, "198.51.100.77:9999") in pending_rows(), pending_rows()
      attribution.succeed("test ! -e /tmp/sched-a.status")
      deny(held_id)
      exit_status("sched-a")
    '';

    shared = ''
      # Two names share one IP. A raw flow to it is judged under one of the
      # names, and the prompt carries the destination IP and the other name.
      shared_script = (
          "getent ahostsv4 shared-a.test >/dev/null; "
          "getent ahostsv4 shared-b.test >/dev/null; "
          + raw_udp(9201, SHARED)
      )
      start_observer("dns-shared")
      start_sandbox("shared", "dns-a-bash", "dns-shared", shared_script)
      prompt_id, destination = wait_pending(9201)
      chosen = destination.rsplit(":", 1)[0]
      assert chosen in ("shared-a.test", "shared-b.test"), f"shared-IP prompt named {destination!r}"
      other = ({"shared-a.test", "shared-b.test"} - {chosen}).pop()
      push = wait_push("dns-shared", 9201)
      base, marker, fragment = push["url"].partition("#agent-sandbox-aliases=")
      assert push["host"] == chosen, f"push host {push['host']!r}, pending host {chosen!r}: {push}"
      assert base == f"udp://{SHARED}:9201", f"push url base {base!r}: {push}"
      assert marker and json.loads(fragment) == [other], f"alias fragment {fragment!r}, want [{other!r}]: {push}"
      deny(prompt_id)
      udp_denied("shared", chosen, 9201)
    '';

    verdict = ''
      # A verdict decided for one name is not replayed for another name on the
      # same IP and port. The second sandbox is attributed to shared-a.test by
      # a flow on another port while shared-a.test is the newest name; the
      # first sandbox then resolves shared-b.test last and is denied for the
      # session. The second sandbox then connects right after that denial and
      # must still be asked: the denial stands neither in the kernel reject nor
      # in a cached verdict for another sandbox.
      session_a_ui = start_observer("dns-deny-a")
      primed_script = (
          "getent ahostsv4 shared-b.test >/dev/null; "
          "getent ahostsv4 shared-a.test >/dev/null; "
          + raw_udp(9301, SHARED)
          + "; "
          + raw_udp(9302, SHARED)
      )
      start_sandbox("deny-b", "dns-b-bash", "dns-deny-b", primed_script)
      primed_id, destination = wait_pending(9301)
      assert destination == "shared-a.test:9301", f"sandbox B first prompt named {destination!r}"

      denied_script = (
          "getent ahostsv4 shared-a.test >/dev/null; "
          "getent ahostsv4 shared-b.test >/dev/null; "
          + raw_udp(9302, SHARED)
      )
      start_sandbox("deny-a", "dns-a-bash", "dns-deny-a", denied_script)
      denied_id, destination = wait_pending(9302)
      assert destination == "shared-b.test:9302", f"sandbox A prompt named {destination!r}"
      deny(denied_id, "session", "--session-id", session_a_ui)
      udp_denied("deny-a", "shared-b.test", 9302)
      assert_no_pending(9302)

      deny(primed_id)
      prompt_id, destination = wait_pending(9302, timeout=30)
      assert destination == "shared-a.test:9302", f"sandbox B second prompt named {destination!r}"
      deny(prompt_id)
      udp_denied("deny-b", "shared-a.test", 9302)
    '';

  };
  # DNS upstream behind the forwarder. Answers are fixed per name; two names
  # share one address, and the forged names make it send datagrams the
  # forwarder must ignore before the real answer.
  upstreamScript = pkgs.writeText "agent-sandbox-vm-dns-upstream.py" ''
    import socket
    import struct
    import threading
    import time

    ADDRESS = ("169.254.100.1", 5353)
    LOG = "/var/log/dns-upstream.log"
    DECOY = "198.51.100.66"
    DECOY_TCP = "198.51.100.67"
    ANSWERS = {
        "forged.test": "198.51.100.10",
        "tcp-forged.test": "198.51.100.12",
        "tcp-ok.test": "198.51.100.11",
        "shared-a.test": "198.51.100.50",
        "shared-b.test": "198.51.100.50",
        "probe.test": "198.51.100.200",
        "evil?.test": "198.51.100.90",
        "two words.test": "198.51.100.90",
        "frag#x.test": "198.51.100.90",
        "benign-h2.test": "198.51.100.90",
        "benign-h.test": "198.51.100.90",
        "x-a.test": "198.51.100.95",
        "x-b.test": "198.51.100.95",
    }


    def encode_name(name):
        labels = [bytes([len(label)]) + label.encode() for label in name.split(".")]
        return b"".join(labels) + b"\x00"


    OTHER_QUESTION = encode_name("other.test") + struct.pack("!HH", 1, 1)


    def log(event):
        with open(LOG, "a") as handle:
            handle.write(event + "\n")


    def parse(data):
        index = 12
        labels = []
        while data[index]:
            length = data[index]
            labels.append(data[index + 1 : index + 1 + length].decode())
            index += length + 1
        qtype = struct.unpack("!H", data[index + 1 : index + 3])[0]
        query_id = struct.unpack("!H", data[:2])[0]
        return query_id, ".".join(labels), qtype, data[12 : index + 5]


    def reply(query_id, question, address):
        answer = b""
        if address:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(address)
        header = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1 if address else 0, 0, 0)
        return header + question + answer


    def replies(data, tcp):
        query_id, name, qtype, question = parse(data)
        address = ANSWERS.get(name) if qtype == 1 else None
        if name.startswith("many-") and name.endswith(".test") and qtype == 1:
            address = "198.51.100.91"
        log("query " + name)
        if name == "forged.test" and qtype == 1 and not tcp:
            log("forged-udp " + name)
            return [
                reply(query_id ^ 0xFFFF, question, DECOY),
                reply(query_id, OTHER_QUESTION, DECOY),
                reply(query_id, question, address),
            ]
        if name == "tcp-forged.test" and qtype == 1 and tcp:
            log("forged-tcp " + name)
            return [reply(query_id ^ 0xFFFF, question, DECOY_TCP)]
        return [reply(query_id, question, address)]


    def read_exact(conn, count):
        data = b""
        while len(data) < count:
            chunk = conn.recv(count - len(data))
            if not chunk:
                return None
            data += chunk
        return data


    def handle_tcp(conn):
        with conn:
            while True:
                header = read_exact(conn, 2)
                if header is None:
                    return
                data = read_exact(conn, struct.unpack("!H", header)[0])
                if data is None:
                    return
                for message in replies(data, True):
                    conn.sendall(struct.pack("!H", len(message)) + message)


    def serve_tcp(listener):
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(ADDRESS)

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(ADDRESS)
    tcp.listen(16)
    threading.Thread(target=serve_tcp, args=(tcp,), daemon=True).start()

    while True:
        data, peer = udp.recvfrom(4096)
        for message in replies(data, False):
            udp.sendto(message, peer)
            time.sleep(0.05)
  '';
in
{
  inherit scenarios;

  mkCheck =
    part:
    pkgs.testers.runNixOSTest (_: {
      name = "e2e-dns-attribution-${part}";
      node.specialArgs = { inherit inputs; };
      nodes.attribution = _: node;
      testScript = preamble + scenarios.${part};
    });
}
