{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e) proxyNode;
  # Raw DNS query to the sandbox's resolver with the AD bit set, as glibc sends
  # with `options trust-ad`; prints one `DNSRESULT <json>` line.
  dnsClientScript = pkgs.writeText "agent-sandbox-vm-dns-client.py" ''
    import json
    import socket
    import struct
    import sys

    name, qtype = sys.argv[1], {"A": 1, "HTTPS": 65}[sys.argv[2]]
    server = next(
        line.split()[1] for line in open("/etc/resolv.conf") if line.startswith("nameserver")
    )
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    query = struct.pack(">HHHHHH", 0x4242, 0x0120, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, (server, 53))
    data = sock.recv(65535)
    _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])

    def skip_name(offset):
        while data[offset]:
            if data[offset] & 0xC0 == 0xC0:
                return offset + 2
            offset += 1 + data[offset]
        return offset + 1

    offset = 12
    for _ in range(qdcount):
        offset = skip_name(offset) + 4

    answers = []
    for _ in range(ancount):
        offset = skip_name(offset)
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        answers.append({"type": rtype, "rdata": data[offset : offset + rdlength].hex()})
        offset += rdlength

    print("DNSRESULT " + json.dumps({"rcode": flags & 0xF, "ad": bool(flags & 0x20), "answers": answers}))
  '';
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
  # Canned upstream resolver answering as a DNSSEC-validating resolver would:
  # AD set and RRSIGs alongside the answer.
  signedUpstreamScript = pkgs.writeText "agent-sandbox-vm-signed-dns.py" ''
    import socket
    import struct

    def rr(rtype, rdata):
        return b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata

    def rrsig(covered):
        header = struct.pack(">HBBIIIH", covered, 13, 2, 300, 0xFFFFFFFF, 0, 1)
        return rr(46, header + b"\x04test\x00" + bytes(64))

    https = (
        struct.pack(">H", 1) + b"\x00"
        + struct.pack(">HH", 1, 3) + b"\x02h3"
        + struct.pack(">HHH", 3, 2, 443)
        + struct.pack(">HH", 5, 4) + b"\x01\x02\x03\x04"
    )

    records = {
        ("signed-a.test", 1): [rr(1, bytes([169, 254, 100, 1])), rrsig(1)],
        ("signed-ech.test", 65): [rr(65, https), rrsig(65)],
    }
    names = {name for name, _ in records}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 5354))

    while True:
        query, peer = sock.recvfrom(65535)
        offset, labels = 12, []
        while query[offset]:
            labels.append(query[offset + 1 : offset + 1 + query[offset]].decode().lower())
            offset += 1 + query[offset]
        offset += 1
        (qtype,) = struct.unpack(">H", query[offset : offset + 2])
        name = ".".join(labels)
        answers = records.get((name, qtype), [])
        flags = 0x81A0 if name in names else 0x8183
        header = query[:2] + struct.pack(">HHHHH", flags, 1, len(answers), 0, 0)
        sock.sendto(header + query[12 : offset + 4] + b"".join(answers), peer)
  '';
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-proxy-doh";
  node.specialArgs = { inherit inputs; };

  nodes.proxy = {
    imports = [ proxyNode ];
    agent-sandbox.network.dnsForwardTarget = lib.mkForce "169.254.100.1:5354";

    systemd.services.agent-sandbox-vm-signed-dns = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${signedUpstreamScript}";
    };
  };

  testScript = ''
    import base64
    import json
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

    # DoH: the proxy rewrites the advertised ECH configuration with its
    # own; DNSSEC-authenticated answers are rewritten with the AD bit cleared.
    ech_config = proxy.succeed("base64 -w0 /var/lib/agent-sandbox/proxy/ech-config-list").strip()
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "curl --silent --show-error --fail --max-time 15 -X POST -H 'Content-Type: application/dns-message' --data-binary \"\" -o /tmp/doh-ech.bin http://169.254.100.1:8008/doh-ech && python3 -c 'import base64,sys; expected=base64.b64decode(\"%s\"); data=open(\"/tmp/doh-ech.bin\",\"rb\").read(); sys.exit(0 if expected in data else 1)'" % ech_config,
        wrapper=session_wrapper,
    )
    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "curl --silent --show-error --fail --max-time 15 -X POST -H 'Content-Type: application/dns-message' --data-binary \"\" -o /tmp/doh-dnssec.bin http://169.254.100.1:8008/doh-dnssec && python3 -c 'import base64,sys; expected=base64.b64decode(\"%s\"); data=open(\"/tmp/doh-dnssec.bin\",\"rb\").read(); sys.exit(0 if expected in data and not data[3] & 0x20 else 1)'" % ech_config,
        wrapper=session_wrapper,
    )

    # Forwarder: signed answers it leaves alone keep AD and their RRSIGs;
    # signed answers it must rewrite come back unauthenticated instead of SERVFAIL.
    proxy.wait_for_unit("agent-sandbox-vm-signed-dns.service")

    def sandbox_dns(name, qtype):
        output = sandbox_shell(
            proxy,
            "sandbox-proxy-bash",
            f"python3 ${dnsClientScript} {name} {qtype}",
            wrapper=session_wrapper,
        )
        line = next(line for line in output.splitlines() if line.startswith("DNSRESULT "))
        return json.loads(line.removeprefix("DNSRESULT "))

    signed_a = sandbox_dns("signed-a.test", "A")
    assert signed_a["rcode"] == 0, signed_a
    assert signed_a["ad"], signed_a
    assert [answer["type"] for answer in signed_a["answers"]] == [1, 46], signed_a
    assert signed_a["answers"][0]["rdata"] == "a9fe6401", signed_a

    sandbox_shell(
        proxy,
        "sandbox-proxy-bash",
        "getent ahostsv4 signed-a.test | grep -q '^169.254.100.1 '",
        wrapper=session_wrapper,
    )

    signed_ech = sandbox_dns("signed-ech.test", "HTTPS")
    assert signed_ech["rcode"] == 0, signed_ech
    assert not signed_ech["ad"], signed_ech
    assert [answer["type"] for answer in signed_ech["answers"]] == [65], signed_ech

    rdata = bytes.fromhex(signed_ech["answers"][0]["rdata"])
    assert rdata[2] == 0, signed_ech
    params, offset = {}, 3
    while offset < len(rdata):
        key = int.from_bytes(rdata[offset : offset + 2], "big")
        length = int.from_bytes(rdata[offset + 2 : offset + 4], "big")
        params[key] = rdata[offset + 4 : offset + 4 + length]
        offset += 4 + length
    assert params == {5: base64.b64decode(ech_config)}, params
  '';
})
