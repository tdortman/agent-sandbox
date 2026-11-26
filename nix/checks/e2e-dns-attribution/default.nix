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
    mkBash
    module
    tlsFixture
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
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

  sandboxTools = commonExtraPkgs ++ [
    dnsTcpQuery
    pkgs.getent
    pkgs.python3
  ];

  echoService = socatAddress: {
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      ExecStart = "${pkgs.socat}/bin/socat ${socatAddress} EXEC:${pkgs.coreutils}/bin/cat";
      Restart = "on-failure";
      User = "sandbox";
    };
  };
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-dns-attribution";
  node.specialArgs = { inherit inputs; };

  nodes.attribution =
    _:
    lib.recursiveUpdate baseNode {
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

      virtualisation.cores = 4;

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
    };

  testScript = ''
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
    assert destination == f"{DECOY}:9101", destination
    deny(prompt_id)
    assert exit_status("decoy") != 0

    # Positive control: the real answer is attributed to the queried name.
    start_sandbox("real", "dns-a-bash", "dns-forged-real", raw_connect(9102, "198.51.100.10"))
    prompt_id, destination = wait_pending(9102)
    assert destination == "forged.test:9102", destination
    deny(prompt_id)
    assert exit_status("real") != 0

    # Over TCP the forwarder takes the first reply: a forged one fails the
    # lookup instead of reaching the client, and nothing is attributed.
    answer = run_sandbox("dns-a-bash", "dns-forged-tcp", "dns-tcp-query tcp-forged.test")
    assert "rcode=2 address=none" in answer, answer
    attribution.succeed("grep -q '^forged-tcp ' /var/log/dns-upstream.log")
    answer = run_sandbox("dns-a-bash", "dns-tcp-ok", "dns-tcp-query tcp-ok.test")
    assert "rcode=0 address=198.51.100.11" in answer, answer
    start_sandbox("decoy-tcp", "dns-a-bash", "dns-forged-decoy-tcp", raw_connect(9103, DECOY_TCP))
    prompt_id, destination = wait_pending(9103)
    assert destination == f"{DECOY_TCP}:9103", destination
    deny(prompt_id)
    assert exit_status("decoy-tcp") != 0

    # Two names share one IP. A raw flow to it is judged under one of the
    # names, and the prompt carries the destination IP and the other name.
    shared_script = (
        "getent ahostsv4 shared-a.test >/dev/null; "
        "getent ahostsv4 shared-b.test >/dev/null; "
        + raw_connect(9201, SHARED)
    )
    start_observer("dns-shared")
    start_sandbox("shared", "dns-a-bash", "dns-shared", shared_script)
    prompt_id, destination = wait_pending(9201)
    chosen = destination.rsplit(":", 1)[0]
    assert chosen in ("shared-a.test", "shared-b.test"), destination
    other = ({"shared-a.test", "shared-b.test"} - {chosen}).pop()
    push = wait_push("dns-shared", 9201)
    base, marker, fragment = push["url"].partition("#agent-sandbox-aliases=")
    assert push["host"] == chosen, push
    assert base == f"tcp://{SHARED}:9201", push
    assert marker and json.loads(fragment) == [other], push
    deny(prompt_id)
    assert exit_status("shared") != 0

    # A verdict decided for one name is not replayed for another name on the
    # same IP and port. The second sandbox is attributed to shared-a.test by
    # a flow on another port while shared-a.test is the newest name; the
    # first sandbox then resolves shared-b.test last and is denied for the
    # session. Its transient kernel reject expires before the second sandbox
    # connects, so only a cached verdict could still turn that flow away.
    session_a_ui = start_observer("dns-deny-a")
    primed_script = (
        "getent ahostsv4 shared-b.test >/dev/null; "
        "getent ahostsv4 shared-a.test >/dev/null; "
        + raw_connect(9301, SHARED)
        + "; "
        + raw_connect(9302, SHARED)
    )
    start_sandbox("deny-b", "dns-b-bash", "dns-deny-b", primed_script)
    primed_id, destination = wait_pending(9301)
    assert destination == "shared-a.test:9301", destination

    denied_script = (
        "getent ahostsv4 shared-a.test >/dev/null; "
        "getent ahostsv4 shared-b.test >/dev/null; "
        + raw_connect(9302, SHARED)
    )
    start_sandbox("deny-a", "dns-a-bash", "dns-deny-a", denied_script)
    denied_id, destination = wait_pending(9302)
    assert destination == "shared-b.test:9302", destination
    deny(denied_id, "session", "--session-id", session_a_ui)
    assert exit_status("deny-a") != 0

    time.sleep(7)
    deny(primed_id)
    prompt_id, destination = wait_pending(9302, timeout=30)
    assert destination == "shared-a.test:9302", destination
    deny(prompt_id)
    assert exit_status("deny-b") != 0

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
})
