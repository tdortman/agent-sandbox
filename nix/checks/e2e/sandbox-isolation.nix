{
  lib,
  pkgs,
  inputs,
}:
let
  inherit (e2e)
    baseNode
    commonExtraPkgs
    dialogStub
    dnsService
    mkBash
    module
    observerScript
    tlsFixture
    ;
  # One backend for every port the test dials: the rogue's, the allowed
  # destination and the two the victim has to ask about.
  allowedPort = 18200;
  # Short window so the queue drains in seconds: the derived client policy
  # timeout is approvalTimeout + min(approvalTimeout, 60) + 5 = 45 s.
  approvalTimeout = 20.0;
  askedPort = 18201;
  backendPorts = (lib.range rogueFirstPort (rogueFirstPort + rogueFlows - 1)) ++ [
    allowedPort
    askedPort
    expiringPort
    projectPort
    subPort
    gatePort
    replayPort
    replayDenyPort
    sessionPort
  ];
  backends = pkgs.writeShellScript "agent-sandbox-vm-isolation-backends" ''
    for port in ${lib.concatMapStringsSep " " toString backendPorts}; do
      ${pkgs.socat}/bin/socat TCP4-LISTEN:$port,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat &
    done
    # The verdict cache only serves flows the proxy does not take over, so
    # its scenario dials UDP.
    for port in ${toString allowedPort} ${toString gatePort}; do
      ${pkgs.python3}/bin/python3 ${udpEcho} $port &
    done
    wait
  '';
  e2e = import ./common.nix {
    inherit inputs lib pkgs;
  };
  expiringPort = 18202;
  gatePort = 18205;
  # Every scenario runs against the same node: the daemon, the backends and
  # the helpers below. A check boots it once and runs its parts' scenarios in order.
  # Direct network transport: every flow without a rule is judged by an
  # NFQUEUE handler that waits for the prompt.
  node = lib.recursiveUpdate baseNode {
    imports = [ module ];

    agent-sandbox = {
      enable = true;

      network = {
        enable = true;

        declarativeAllow = [
          {
            host = "169.254.100.1";
            port = allowedPort;
          }
        ];

        dnsForwardTarget = "169.254.100.1:5353";
      };

      packages = [
        (mkBash "sandbox-isolation-bash" {
          extraPkgs = commonExtraPkgs ++ [ pkgs.python3 ];
        })
      ];

      policy = {
        inherit approvalTimeout;
        uiBackend = "qt-dialog";
      };
    };

    systemd.services = {
      agent-sandbox-policy.environment.AGENT_SANDBOX_QT_DIALOG = "${dialogStub}";
      agent-sandbox-vm-dns = dnsService;

      agent-sandbox-vm-isolation-backends = {
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          ExecStart = "${backends}";
          Restart = "on-failure";
          User = "sandbox";
        };
      };
    };
  };
  preamble = ''
    import shlex

    ROGUE_FIRST_PORT = ${toString rogueFirstPort}
    ROGUE_FLOWS = ${toString rogueFlows}
    ALLOWED_PORT = ${toString allowedPort}
    ASKED_PORT = ${toString askedPort}
    EXPIRING_PORT = ${toString expiringPort}
    PROJECT_PORT = ${toString projectPort}
    GATE_PORT = ${toString gatePort}
    REPLAY_PORT = ${toString replayPort}
    REPLAY_DENY_PORT = ${toString replayDenyPort}
    SESSION_PORT = ${toString sessionPort}
    APPROVAL_TIMEOUT = ${toString (builtins.floor approvalTimeout)}

    # policyd's cap on the approval requests one sandbox scope has in
    # flight (MAX_PROMPTS_PER_SCOPE).
    SCOPE_CAP = 16

    PENDING = "runuser -u sandbox -- agent-sandbox-approve pending"
    ROGUE_RANGE = [f"169.254.100.1:{ROGUE_FIRST_PORT + index}" for index in range(ROGUE_FLOWS)]

    ROGUE = f"""
    import socket, time
    held = []
    for port in range({ROGUE_FIRST_PORT}, {ROGUE_FIRST_PORT + ROGUE_FLOWS}):
        sock = socket.socket()
        sock.setblocking(False)
        try:
            sock.connect(("169.254.100.1", port))
        except BlockingIOError:
            pass
        held.append(sock)
    time.sleep(3600)
    """

    def command(*args):
        return shlex.join(str(arg) for arg in args)

    def client_bg(script, out):
        # A fresh sandbox per call, so every client has its own agent scope.
        # Stdio is fully detached so the driver's shell returns while the
        # sandbox waits.
        inner = f"cd /home/user && {shlex.join(['sandbox-isolation-bash', '-c', script])}"
        detached = (
            f"nohup runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 sh -c {shlex.quote(inner)} "
            f"</dev/null >{out} 2>&1 &"
        )
        isolation.succeed(command("sh", "-c", detached))

    def tcp_client(port, out):
        client_bg(
            f"printf {port}-ok | socat -T 120 - TCP4:169.254.100.1:{port}; printf '\\nexit=%s\\n' $?",
            out,
        )

    def pending_lines():
        return isolation.succeed(f"{PENDING} || true").splitlines()

    def rogue_pending():
        return sum(any(flow in line for flow in ROGUE_RANGE) for line in pending_lines())

    def wait_pending(needle, timeout=30):
        isolation.wait_until_succeeds(f"{PENDING} | grep -F -q {shlex.quote(needle)}", timeout=timeout)

    def pending_id(needle):
        return isolation.succeed(f"{PENDING} | grep -F {shlex.quote(needle)} | head -1").split("\t")[0]

    start_all()
    isolation.wait_for_unit("multi-user.target")
    isolation.wait_for_unit("agent-sandbox-netns.service")
    isolation.wait_for_unit("agent-sandbox-nfq.service")
    isolation.wait_for_unit("agent-sandbox-policy.service")
    isolation.wait_for_unit("agent-sandbox-vm-isolation-backends.service")
    isolation.wait_for_open_port(ALLOWED_PORT)

    def project_bg(project, session, flow, out):
        # The wrapper takes the session id from the environment, so the
        # scenario knows it before the sandbox starts.
        script = f"{flow}; printf '\\nexit=%s\\n' $?"
        inner = f"cd /home/user/{project} && {shlex.join(['sandbox-isolation-bash', '-c', script])}"
        detached = (
            f"nohup runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 AGENT_SANDBOX_SESSION_ID={session} "
            f"sh -c {shlex.quote(inner)} </dev/null >{out} 2>&1 &"
        )
        isolation.succeed(command("sh", "-c", detached))

    def flood_rogue():
        client_bg(f"python3 -c {shlex.quote(ROGUE)}", "/tmp/rogue.out")
        isolation.wait_until_succeeds(f"test {SCOPE_CAP} -le $({PENDING} | grep -c -F 169.254.100.1:181 || true)", timeout=60)

    def stop_rogue():
        # Kill the flooder so its retried SYNs raise no new prompts, then wait
        # for the prompts it left to expire. The bracket keeps pkill from
        # matching its own command line.
        isolation.succeed("pkill -f '[h]eld = \\[\\]'")
        isolation.wait_until_succeeds(f"test 0 -eq $({PENDING} | grep -c -F 169.254.100.1:181 || true)", timeout=60)
  '';
  projectPort = 18203;
  # The verdict cache needs the proxy's uid, so only the part that exercises it
  # enables the proxy.
  proxyModule.agent-sandbox.network.httpProxy = {
    enable = true;
    caCertificateFile = "${tlsFixture}/ca-cert.pem";
    caPrivateKeyFile = "${tlsFixture}/ca-key.pem";
    upstreamAllowCidrs = [ "169.254.100.1/32" ];
  };
  replayDenyPort = 18207;
  replayPort = 18206;
  # The rogue sandbox opens more flows at once than the daemon has handlers,
  # then idles: every flow waits on a prompt nobody answers.
  rogueFirstPort = 18100;
  rogueFlows = 24;
  scenarios = {
    cache = ''
      import json
      import time

      # 7. A cached verdict belongs to the sandbox it was decided for. All
      # sandboxes share one network namespace, so the kernel gate and the
      # NFQUEUE daemon key every cached verdict by the connecting sandbox's
      # cgroup as well. The first project allows GATE_PORT and the second
      # denies ALLOWED_PORT, which the declarative layer allows for everyone.
      isolation.succeed("journalctl --no-pager -b -u agent-sandbox-nfq.service | grep -q 'verdict cache enabled'")

      def write_project_policy(project, kind, port):
          policy = json.dumps({"network": {"direct": {kind: [{"host": "169.254.100.1", "port": port}]}}})
          isolation.succeed(
              command(
                  "runuser", "-u", "sandbox", "--", "sh", "-c",
                  f"mkdir -p /home/user/{project}/.agent-sandbox && printf %s {shlex.quote(policy)}"
                  f" > /home/user/{project}/.agent-sandbox/policy.json",
              )
          )

      def gate_flow(port):
          return f"printf '{port}-ok\\n' | timeout 10 socat -T 3 - UDP4:169.254.100.1:{port} | grep -x {port}-ok"

      def cache_hits(port):
          # Flows the NFQUEUE daemon answered from the verdict cache.
          return int(isolation.succeed(
              "journalctl --no-pager -b -u agent-sandbox-nfq.service | grep -F 'accept (policy cache)' "
              f"| grep -c -F 'port={port}' || true"
          ).strip())

      def ask_and_deny(port):
          wait_pending(f"169.254.100.1:{port}")
          isolation.succeed(
              command(
                  "runuser", "-u", "sandbox", "--", "agent-sandbox-approve", "deny",
                  pending_id(f"169.254.100.1:{port}"),
              )
          )

      def wait_exit(out):
          isolation.wait_until_succeeds(f"grep -q '^exit=' {out}", timeout=30)

      write_project_policy("proj-g", "allow", GATE_PORT)
      write_project_policy("proj-h", "deny", ALLOWED_PORT)

      # The first sandbox is allowed by its project policy, and its second
      # flow is answered from the cache without a policyd round trip.
      hits = cache_hits(GATE_PORT)
      project_bg("proj-g", "vm-session-g", f"{gate_flow(GATE_PORT)} && {gate_flow(GATE_PORT)}", "/tmp/gate-a.out")
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/gate-a.out", timeout=30)
      isolation.succeed(f"test \"$(grep -cx {GATE_PORT}-ok /tmp/gate-a.out)\" = 2")
      # The first UDP flow's own second packet already counts as a hit, so a
      # repeat flow served from the cache brings the count to two.
      served = cache_hits(GATE_PORT)
      assert served >= hits + 2, "the repeat flow was not served from the verdict cache"

      # A sandbox of another project connecting to the same destination is
      # asked, not served the first sandbox's cached allow.
      project_bg("proj-h", "vm-session-h", gate_flow(GATE_PORT), "/tmp/gate-b.out")
      ask_and_deny(GATE_PORT)
      wait_exit("/tmp/gate-b.out")
      isolation.fail("grep -q '^exit=0' /tmp/gate-b.out")
      isolation.fail(f"grep -q {GATE_PORT}-ok /tmp/gate-b.out")
      assert cache_hits(GATE_PORT) == served, "another sandbox was served from the first sandbox's cached allow"

      # The second sandbox's denial neither hides the first sandbox's allow
      # nor survives in it. The transient kernel reject the denial added has
      # expired by now, so only a cached verdict could still turn the flow away.
      time.sleep(7)
      project_bg("proj-g", "vm-session-g2", gate_flow(GATE_PORT), "/tmp/gate-a2.out")
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/gate-a2.out", timeout=30)
      isolation.succeed(f"grep -q {GATE_PORT}-ok /tmp/gate-a2.out")

      # Deny wins per sandbox: the first sandbox caches the globally allowed
      # destination, and the second sandbox, whose project denies it, is still
      # refused without a prompt.
      hits = cache_hits(ALLOWED_PORT)
      project_bg("proj-g", "vm-session-g3", f"{gate_flow(ALLOWED_PORT)} && {gate_flow(ALLOWED_PORT)}", "/tmp/gate-a3.out")
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/gate-a3.out", timeout=30)
      served = cache_hits(ALLOWED_PORT)
      assert served >= hits + 2, "the globally allowed repeat flow was not served from the verdict cache"

      project_bg("proj-h", "vm-session-h2", gate_flow(ALLOWED_PORT), "/tmp/gate-b2.out")
      wait_exit("/tmp/gate-b2.out")
      isolation.fail("grep -q '^exit=0' /tmp/gate-b2.out")
      isolation.fail(f"grep -q {ALLOWED_PORT}-ok /tmp/gate-b2.out")
      isolation.fail(f"{PENDING} | grep -F -q 169.254.100.1:{ALLOWED_PORT}")
      assert cache_hits(ALLOWED_PORT) == served, "the project deny was bypassed by another sandbox's cached allow"
    '';

    cap = ''
      import time

      # 1. A rogue sandbox opens more flows than the daemon has handlers and
      # leaves every one of them waiting on a prompt. policyd holds it to its
      # per-sandbox cap: the surplus flows are refused at once instead of
      # queueing, so a rogue never holds more than the cap's worth of
      # handlers, connections and prompts.
      flood_rogue()
      time.sleep(5)
      assert rogue_pending() == SCOPE_CAP, f"rogue queued {rogue_pending()} prompts, cap is {SCOPE_CAP}"

      # 2. Meanwhile a second sandbox's new connections are judged. One that
      # needs no prompt completes within seconds.
      tcp_client(ALLOWED_PORT, "/tmp/allowed.out")
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/allowed.out", timeout=20)
      isolation.succeed(f"grep -q {ALLOWED_PORT}-ok /tmp/allowed.out")

      # 3. One that needs a prompt is queued, not refused with a cap error,
      # and its answer reaches the client.
      tcp_client(ASKED_PORT, "/tmp/asked.out")
      wait_pending(f"169.254.100.1:{ASKED_PORT}")
      isolation.fail("grep -q '^exit=' /tmp/asked.out")
      isolation.succeed(
          command(
              "runuser", "-u", "sandbox", "--", "agent-sandbox-approve", "approve",
              pending_id(f"169.254.100.1:{ASKED_PORT}"), "once",
          )
      )
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/asked.out", timeout=20)
      isolation.succeed(f"grep -q {ASKED_PORT}-ok /tmp/asked.out")
    '';

    fairness = ''
      import time

      flood_rogue()

      # 4. A prompt of the second sandbox nobody answers reaches the head of
      # the line while the rogue's backlog is still queued: its own window
      # opens and expires, and its client is refused. Queued behind the
      # whole backlog it would wait one window per rogue prompt.
      tcp_client(EXPIRING_PORT, "/tmp/expiring.out")
      wait_pending(f"169.254.100.1:{EXPIRING_PORT}")
      queued_at = time.monotonic()
      isolation.wait_until_succeeds("grep -q '^exit=' /tmp/expiring.out", timeout=6 * APPROVAL_TIMEOUT)
      isolation.fail("grep -q '^exit=0' /tmp/expiring.out")
      waited = time.monotonic() - queued_at
      assert waited < 5 * APPROVAL_TIMEOUT, f"prompt waited {waited:.0f}s behind another sandbox's backlog"
      remaining = rogue_pending()
      assert remaining >= SCOPE_CAP // 2, f"rogue backlog drained to {remaining}: the test proved nothing"

      # The rogue never starved the daemon: a further flow is still judged.
      tcp_client(ALLOWED_PORT, "/tmp/allowed-again.out")
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/allowed-again.out", timeout=20)

      # Leave no backlog for the scenario that follows on this VM.
      stop_rogue()
    '';

    project = ''
      # 5. A project-scoped allow belongs to its own project. The first
      # sandbox runs in one project and answers its prompt with the project
      # scope. A second sandbox in the same project is then allowed without a
      # prompt. A sandbox in another project sets the environment its
      # processes read, the first sandbox's session id and project root, and
      # is still judged as itself: it is asked, and its client is refused.
      isolation.succeed("runuser -u sandbox -- mkdir -p /home/user/proj-a /home/user/proj-b /home/user/proj-c")

      PROJECT_FLOW = f"printf {PROJECT_PORT}-ok | socat -T 120 - TCP4:169.254.100.1:{PROJECT_PORT}"

      project_bg("proj-a", "vm-session-a", PROJECT_FLOW, "/tmp/project-a.out")
      wait_pending(f"169.254.100.1:{PROJECT_PORT}")
      isolation.succeed(
          command(
              "runuser", "-u", "sandbox", "--", "agent-sandbox-approve", "approve",
              pending_id(f"169.254.100.1:{PROJECT_PORT}"), "project",
          )
      )
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/project-a.out", timeout=20)
      isolation.succeed(f"grep -q {PROJECT_PORT}-ok /tmp/project-a.out")

      # The same project is allowed without a prompt.
      project_bg("proj-a", "vm-session-a2", PROJECT_FLOW, "/tmp/project-a2.out")
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/project-a2.out", timeout=20)
      isolation.succeed(f"grep -q {PROJECT_PORT}-ok /tmp/project-a2.out")

      # Another project is asked, whatever its processes claim.
      forged = (
          f"printf {PROJECT_PORT}-ok | env AGENT_SANDBOX_PROJECT_ROOT=/home/user/proj-a "
          f"AGENT_SANDBOX_SESSION_ID=vm-session-a socat -T 120 - TCP4:169.254.100.1:{PROJECT_PORT}"
      )
      project_bg("proj-b", "vm-session-b", forged, "/tmp/project-b.out")
      wait_pending(f"169.254.100.1:{PROJECT_PORT}")
      isolation.fail("grep -q '^exit=' /tmp/project-b.out")
      isolation.succeed(
          command(
              "runuser", "-u", "sandbox", "--", "agent-sandbox-approve", "deny",
              pending_id(f"169.254.100.1:{PROJECT_PORT}"),
          )
      )
      isolation.wait_until_succeeds("grep -q '^exit=' /tmp/project-b.out", timeout=20)
      isolation.fail("grep -q '^exit=0' /tmp/project-b.out")
      isolation.fail(f"grep -q {PROJECT_PORT}-ok /tmp/project-b.out")

      # 6. A project file inside a subdirectory is not project policy. A
      # sandbox writes one that allows a port, into a directory of its own
      # project. A sandbox whose project is that subdirectory is allowed by
      # it, which shows the file is a valid policy. A process of the first
      # project that claims the subdirectory as its project root is still
      # asked.
      SUB_PORT = ${toString subPort}
      sub_policy = (
          '{"network":{"direct":{"allow":[{"host":"169.254.100.1","port":' + str(SUB_PORT) + '}]}}}'
      )
      project_bg(
          "proj-c", "vm-session-c",
          "mkdir -p sub/.agent-sandbox && printf %s " + shlex.quote(sub_policy)
          + " > sub/.agent-sandbox/policy.json",
          "/tmp/project-c-write.out",
      )
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/project-c-write.out", timeout=30)
      isolation.succeed("test -s /home/user/proj-c/sub/.agent-sandbox/policy.json")

      sub_flow = f"printf {SUB_PORT}-ok | socat -T 120 - TCP4:169.254.100.1:{SUB_PORT}"
      project_bg("proj-c/sub", "vm-session-c-sub", sub_flow, "/tmp/project-c-sub.out")
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/project-c-sub.out", timeout=20)
      isolation.succeed(f"grep -q {SUB_PORT}-ok /tmp/project-c-sub.out")

      claimed = (
          f"printf {SUB_PORT}-ok | env AGENT_SANDBOX_PROJECT_ROOT=/home/user/proj-c/sub "
          f"socat -T 120 - TCP4:169.254.100.1:{SUB_PORT}"
      )
      project_bg("proj-c", "vm-session-c2", claimed, "/tmp/project-c-claim.out")
      wait_pending(f"169.254.100.1:{SUB_PORT}")
      isolation.fail("grep -q '^exit=' /tmp/project-c-claim.out")
      isolation.succeed(
          command(
              "runuser", "-u", "sandbox", "--", "agent-sandbox-approve", "deny",
              pending_id(f"169.254.100.1:{SUB_PORT}"),
          )
      )
      isolation.wait_until_succeeds("grep -q '^exit=' /tmp/project-c-claim.out", timeout=20)
      isolation.fail("grep -q '^exit=0' /tmp/project-c-claim.out")
      isolation.fail(f"grep -q {SUB_PORT}-ok /tmp/project-c-claim.out")
    '';

    replay = ''
      import json
      import time

      # 8. A verdict decided for one sandbox does not answer another one.
      # policyd keeps every verdict for a moment so that a connection retried
      # at once is not asked twice. The first sandbox's once approval must not
      # reach a second sandbox that asks for the same destination right
      # after: it waits in a loop of its own and connects the instant the
      # approval is given, well inside that moment.

      def write_project_policy(project, section):
          policy = json.dumps({"network": {"direct": section}})
          isolation.succeed(
              command(
                  "runuser", "-u", "sandbox", "--", "sh", "-c",
                  f"mkdir -p /home/user/{project}/.agent-sandbox && printf %s {shlex.quote(policy)}"
                  f" > /home/user/{project}/.agent-sandbox/policy.json",
              )
          )

      def rule(port):
          return [{"host": "169.254.100.1", "port": port}]

      # Two different project policies. The first allows something unrelated,
      # the second denies the destination of the second round.
      write_project_policy("proj-ra", {"allow": rule(GATE_PORT)})
      write_project_policy("proj-rb", {"deny": rule(REPLAY_DENY_PORT)})

      def flow(port):
          return f"printf {port}-ok | socat -T 20 - TCP4:169.254.100.1:{port}"

      def waiting_client(project, session, tag, port, out):
          # Up and ready before the first sandbox is approved, connecting the
          # moment the go file appears.
          script = (
              f"touch /home/user/{project}/ready-{tag}; "
              f"until test -e /home/user/{project}/go-{tag}; do sleep 0.02; done; {flow(port)}"
          )
          project_bg(project, session, script, out)
          isolation.wait_until_succeeds(f"test -e /home/user/{project}/ready-{tag}", timeout=60)

      def approve_once_and_release(port, project, tag):
          isolation.succeed(
              command(
                  "runuser", "-u", "sandbox", "--", "agent-sandbox-approve", "approve",
                  pending_id(f"169.254.100.1:{port}"), "once",
              )
              + f" && touch /home/user/{project}/go-{tag}"
          )

      isolation.succeed("runuser -u sandbox -- mkdir -p /home/user/proj-ra /home/user/proj-rb")

      # The second sandbox is asked, not served the first one's approval.
      project_bg("proj-ra", "vm-session-ra", flow(REPLAY_PORT), "/tmp/replay-a.out")
      wait_pending(f"169.254.100.1:{REPLAY_PORT}")
      waiting_client("proj-rb", "vm-session-rb", "one", REPLAY_PORT, "/tmp/replay-b.out")
      approve_once_and_release(REPLAY_PORT, "proj-rb", "one")
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/replay-a.out", timeout=20)
      isolation.succeed(f"grep -q {REPLAY_PORT}-ok /tmp/replay-a.out")

      wait_pending(f"169.254.100.1:{REPLAY_PORT}", timeout=15)
      time.sleep(2)
      isolation.fail("grep -q '^exit=' /tmp/replay-b.out")
      isolation.succeed(
          command(
              "runuser", "-u", "sandbox", "--", "agent-sandbox-approve", "deny",
              pending_id(f"169.254.100.1:{REPLAY_PORT}"),
          )
      )
      isolation.wait_until_succeeds("grep -q '^exit=' /tmp/replay-b.out", timeout=20)
      isolation.fail("grep -q '^exit=0' /tmp/replay-b.out")
      isolation.fail(f"grep -q {REPLAY_PORT}-ok /tmp/replay-b.out")

      # A second sandbox whose own project denies the destination is refused
      # outright, whatever the first sandbox was just granted.
      project_bg("proj-ra", "vm-session-ra2", flow(REPLAY_DENY_PORT), "/tmp/replay-a2.out")
      wait_pending(f"169.254.100.1:{REPLAY_DENY_PORT}")
      waiting_client("proj-rb", "vm-session-rb2", "two", REPLAY_DENY_PORT, "/tmp/replay-b2.out")
      approve_once_and_release(REPLAY_DENY_PORT, "proj-rb", "two")
      isolation.wait_until_succeeds("grep -q '^exit=0' /tmp/replay-a2.out", timeout=20)
      isolation.wait_until_succeeds("grep -q '^exit=' /tmp/replay-b2.out", timeout=20)
      isolation.fail("grep -q '^exit=0' /tmp/replay-b2.out")
      isolation.fail(f"grep -q {REPLAY_DENY_PORT}-ok /tmp/replay-b2.out")
      isolation.fail(f"{PENDING} | grep -F -q 169.254.100.1:{REPLAY_DENY_PORT}")
    '';

    session = ''
      # json comes from the replay scenario that runs before this one.
      # 9. A session id is not a credential. The first sandbox's session
      # holds a session-scoped approval. A sandbox that names that session on
      # the policy socket is judged as itself and is asked, however it came by
      # the id.
      def start_observer(session):
          out = f"/tmp/ui-{session}.log"
          isolation.succeed(command("sh", "-c",
              f"nohup runuser -u sandbox -- ${pkgs.python3}/bin/python3 ${observerScript} {session} {out} "
              f"</dev/null >/tmp/ui-{session}.err 2>&1 &"))
          isolation.wait_until_succeeds(f"grep -q '^registered ' {out}", timeout=30)
          return isolation.succeed(f"sed -n 's/^registered //p' {out}").strip()

      def flow(port):
          return f"printf {port}-ok | socat -T 20 - TCP4:169.254.100.1:{port}"

      isolation.succeed("runuser -u sandbox -- mkdir -p /home/user/proj-sa /home/user/proj-sb")
      ui_session = start_observer("vm-session-sa")

      # The first sandbox is asked, the answer covers its session, and its
      # second flow to the same destination needs no prompt. It then stays
      # up, so its session and the approval stay live.
      project_bg(
          "proj-sa", "vm-session-sa",
          f"{flow(SESSION_PORT)}; {flow(SESSION_PORT)}; touch /home/user/proj-sa/done; sleep 3600",
          "/tmp/session-a.out",
      )
      wait_pending(f"169.254.100.1:{SESSION_PORT}")
      isolation.succeed(
          command(
              "runuser", "-u", "sandbox", "--", "agent-sandbox-approve", "approve",
              pending_id(f"169.254.100.1:{SESSION_PORT}"), "session", "--session-id", ui_session,
          )
      )
      isolation.wait_until_succeeds("test -e /home/user/proj-sa/done", timeout=30)
      isolation.succeed(f"test \"$(grep -o {SESSION_PORT}-ok /tmp/session-a.out | wc -l)\" = 2")
      isolation.fail(f"{PENDING} | grep -F -q 169.254.100.1:{SESSION_PORT}")

      # A second sandbox asks the policy socket for the same destination and
      # names the first sandbox's session. The reply says whether it was
      # allowed.
      CLAIM = json.dumps({
          "op": "check",
          "host": "169.254.100.1",
          "connect_host": "169.254.100.1",
          "port": SESSION_PORT,
          "scheme": "tcp",
          "url": f"tcp://169.254.100.1:{SESSION_PORT}",
          "ctx": {"sandbox_session_id": "vm-session-sa"},
      })
      claim_script = (
          "import socket\n"
          "sock = socket.socket(socket.AF_UNIX)\n"
          "sock.connect('/run/agent-sandbox/shared/sandbox-policy.sock')\n"
          f"sock.sendall(({CLAIM!r} + chr(10)).encode())\n"
          "print('reply ' + sock.makefile().readline())\n"
      )
      project_bg("proj-sb", "vm-session-sb", f"python3 -c {shlex.quote(claim_script)}", "/tmp/session-b.out")
      wait_pending(f"169.254.100.1:{SESSION_PORT}")
      # The prompt belongs to no session, so the approver CLI cannot answer it.
      # It times out into a denial.
      isolation.wait_until_succeeds("grep -q '^reply ' /tmp/session-b.out", timeout=60)
      isolation.fail("grep -E -q 'allowed.{1,4}true' /tmp/session-b.out")
    '';
  };
  sessionPort = 18208;
  subPort = 18204;
  # One socket answers every client, unlike socat's forking UDP listener,
  # which loses datagrams of a second client while the first one's child lives.
  udpEcho = pkgs.writeText "agent-sandbox-vm-udp-echo.py" ''
    import socket
    import sys

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", int(sys.argv[1])))
    while True:
        data, peer = sock.recvfrom(4096)
        sock.sendto(data, peer)
  '';
in
{
  mkCheck =
    name: parts:
    pkgs.testers.runNixOSTest (_: {
      name = "e2e-sandbox-isolation-${name}";
      node.specialArgs = { inherit inputs; };
      nodes.isolation = if lib.elem "cache" parts then lib.recursiveUpdate node proxyModule else node;
      testScript = preamble + lib.concatMapStringsSep "\n" (part: scenarios.${part}) parts;
    });
}
