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
    ;
  e2e = import ../e2e/common.nix {
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
  tcpPort = 18300;
  udpPort = 18301;
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-dns-attribution-reject";
  node.specialArgs = { inherit inputs; };

  # Direct network transport with no prompts: a flow no policy layer allows is
  # judged denied by the NFQUEUE handler, which fails it fast with a reset
  # (TCP) or an ICMP unreachable (UDP).
  nodes.reject =
    _:
    lib.recursiveUpdate baseNode {
      imports = [ module ];

      agent-sandbox = {
        enable = true;
        network.enable = true;
        packages = [ (mkBash "reject-bash" { extraPkgs = commonExtraPkgs; }) ];

        policy = {
          interactiveApproval = false;
          uiBackend = "none";
        };
      };

      systemd.services = {
        agent-sandbox-vm-tcp-echo = echoService "TCP4-LISTEN:${toString tcpPort},fork,reuseaddr";
        agent-sandbox-vm-udp-echo = echoService "UDP4-RECVFROM:${toString udpPort},fork,reuseaddr";
      };
    };

  testScript = ''
    import json
    import shlex

    TCP_PORT = ${toString tcpPort}
    UDP_PORT = ${toString udpPort}
    HOST = "169.254.100.1"
    session_env = [
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    ]

    def start_sandbox(tag, project, session, script):
        # Detached, with the output and exit status recorded for later.
        inner = f"cd /home/user/{project} && {shlex.join(['reject-bash', '-c', script])}"
        line = shlex.join([
            "runuser", "-u", "sandbox", "--", "env", *session_env,
            f"AGENT_SANDBOX_SESSION_ID={session}", "sh", "-c", inner,
        ])
        reject.succeed(shlex.join([
            "sh", "-c",
            f"nohup sh -c {shlex.quote(line + '; echo $? > /tmp/' + tag + '.status')} "
            f"</dev/null >/tmp/{tag}.out 2>&1 &",
        ]))

    def wait_done(tag, timeout=90):
        reject.wait_until_succeeds(f"test -s /tmp/{tag}.status", timeout=timeout)
        return reject.succeed(f"cat /tmp/{tag}.out")

    def flow(kind, port, payload):
        return f"printf {payload} | socat -T 20 - {kind}:{HOST}:{port}"

    def nfq_rejects(port):
        return int(reject.succeed(
            "journalctl --no-pager -b -u agent-sandbox-nfq.service "
            f"| grep -F 'reject (policy)' | grep -c -F 'port={port}' || true"
        ).strip())

    start_all()
    reject.wait_for_unit("multi-user.target")
    reject.wait_for_unit("agent-sandbox-netns.service")
    reject.wait_for_unit("agent-sandbox-nfq.service")
    reject.wait_for_unit("agent-sandbox-policy.service")
    reject.wait_for_unit("agent-sandbox-vm-tcp-echo.service")
    reject.wait_for_unit("agent-sandbox-vm-udp-echo.service")
    reject.wait_for_open_port(TCP_PORT)

    # A denial leaves no per-destination state behind for other flows to hit.
    rules = reject.succeed("ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} list table inet agent_sandbox")
    assert "reject_v4" not in rules and "reject_v6" not in rules, rules

    # Only the second sandbox's project allows the destinations.
    project_policy = json.dumps({"network": {"direct": {"allow": [
        {"host": HOST, "port": TCP_PORT},
        {"host": HOST, "port": UDP_PORT},
    ]}}})
    reject.succeed(shlex.join([
        "runuser", "-u", "sandbox", "--", "sh", "-c",
        "mkdir -p /home/user/proj-a /home/user/proj-b/.agent-sandbox && printf %s "
        + shlex.quote(project_policy) + " > /home/user/proj-b/.agent-sandbox/policy.json",
    ]))

    # The second sandbox is up and waiting before the first is denied, so its
    # flows start moments after the denial.
    start_sandbox(
        "b", "proj-b", "reject-b",
        "touch ready; while [ ! -e go ]; do sleep 0.1; done; "
        + flow("TCP4", TCP_PORT, "b-tcp") + "; echo tcp-exit=$?; "
        + flow("UDP4", UDP_PORT, "b-udp") + "; echo udp-exit=$?",
    )
    reject.wait_until_succeeds("test -e /home/user/proj-b/ready", timeout=60)

    # The first sandbox is denied both destinations and fails fast: socat reports
    # the reset or the ICMP unreachable instead of waiting out its timeout.
    start_sandbox(
        "a", "proj-a", "reject-a",
        "start=$(date +%s); "
        + flow("TCP4", TCP_PORT, "a-tcp") + "; echo tcp-exit=$?; "
        + flow("UDP4", UDP_PORT, "a-udp") + "; echo udp-exit=$?; "
        + "echo elapsed=$(( $(date +%s) - start ))",
    )
    first = wait_done("a")
    reject.succeed("runuser -u sandbox -- touch /home/user/proj-b/go")
    tcp_part, _, rest = first.partition("tcp-exit=1")
    udp_part, _, _ = rest.partition("udp-exit=1")
    assert "Connection refused" in tcp_part, f"TCP was not reset:\n{first}"
    assert "Connection refused" in udp_part, f"UDP got no ICMP unreachable:\n{first}"
    elapsed = int(first.split("elapsed=")[1].split()[0])
    assert elapsed < 10, f"denied flows took {elapsed}s: not a fast failure\n{first}"
    assert nfq_rejects(TCP_PORT) >= 1 and nfq_rejects(UDP_PORT) >= 1, "nfq did not judge the first sandbox"

    # The second sandbox reaches the same destinations right after: the first
    # sandbox's denial does not reject them for anyone else.
    second = wait_done("b")
    assert "b-tcp" in second and "tcp-exit=0" in second, second
    assert "b-udp" in second and "udp-exit=0" in second, second
    assert "Connection refused" not in second, second
  '';
})
