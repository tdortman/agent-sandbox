{
  lib,
  pkgs,
  inputs,
}:
let
  inherit (e2e)
    baseNode
    commonExtraPkgs
    installPolicy
    mkBash
    module
    resourceApprovalPolicy
    tlsFixture
    ;
  # Short window: the derived client policy timeout is
  # approvalTimeout + min(approvalTimeout, 60) + 5 = 45 s.
  approvalTimeout = 20.0;
  # Stands in for the Qt dialog: it logs the review request under its own pid
  # and then blocks like a dialog nobody answered. The UI kills it when the
  # prompt is settled elsewhere, so a dead pid means the dialog closed.
  dialogStub = pkgs.writeShellScript "agent-sandbox-vm-dialog-stub" ''
    IFS= read -r request
    printf '%s %s\n' "$$" "$request" >> /tmp/dialog-stub.log
    exec ${pkgs.coreutils}/bin/sleep 3600
  '';
  e2e = import ./common.nix {
    inherit inputs lib pkgs;
  };
  # Network prompts through the HTTP proxy: the policy client's silence
  # timeout against policyd heartbeats.
  heartbeatNode =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate uiConfig {
        imports = [ module ];

        agent-sandbox = {
          enable = true;

          network = {
            enable = true;
            dnsForwardTarget = "169.254.100.1:5353";

            httpProxy = {
              enable = true;
              caCertificateFile = "${tlsFixture}/ca-cert.pem";
              caPrivateKeyFile = "${tlsFixture}/ca-key.pem";
              upstreamAllowCidrs = [ "169.254.100.1/32" ];
            };

            # Below the derived minimum, so the derived value applies.
            policyTimeout = 5.0;
          };

          packages = [
            (mkBash "sandbox-queue-net-bash" {
              extraPkgs = commonExtraPkgs;
            })
          ];
        };

        networking.firewall.interfaces.asbx-test-host.allowedTCPPorts = tcpPorts;

        systemd.services = {
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
        }
        // lib.listToAttrs (
          map (
            port:
            lib.nameValuePair "agent-sandbox-vm-tcp-${toString port}" {
              wantedBy = [ "multi-user.target" ];

              serviceConfig = {
                ExecStart = "${pkgs.socat}/bin/socat TCP4-LISTEN:${toString port},fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
                Restart = "on-failure";
                User = "sandbox";
              };
            }
          ) tcpPorts
        );
      }
    );
  nodeConfigs = {
    heartbeat = heartbeatNode;
    queued = queuedNode;
  };
  # Boot-and-wait shared by every part on a node.
  setups = {
    heartbeat = ''
      start_all()
      heartbeat.wait_for_unit("multi-user.target")
    '';
    queued = ''
      start_all()
      queued.wait_for_unit("multi-user.target")
      queued.wait_for_unit("agent-sandbox-policy.service")
      queued.wait_for_unit("agent-sandbox-vm-queue-sockets.service")
      for socket_name in ${builtins.toJSON unixSockets}:
          queued.wait_until_succeeds(f"test -S {SOCKET_DIR}/{socket_name}.sock")
    '';
  };
  parts = {
    coalesce = {
      body = ''
        # 1. Two processes of one sandbox ask for the same socket at the same
        # moment. They are one requester: one prompt, one dialog, and one
        # answer releases both.
        PAIR = """
        import socket, threading

        barrier = threading.Barrier(2)
        echoed = {}

        def ask(tag):
            sock = socket.socket(socket.AF_UNIX)
            barrier.wait()
            sock.connect("/run/agent-sandbox-test/q2same.sock")
            sock.sendall(tag.encode())
            sock.shutdown(socket.SHUT_WR)
            echoed[tag] = sock.makefile().read()

        threads = [threading.Thread(target=ask, args=(tag,)) for tag in ("one-ok", "two-ok")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        print(sorted(echoed.values()))
        print("exit=0")
        """
        client_bg(queued, "sandbox-queue-bash", f"python3 -c {shlex.quote(PAIR)}", "/tmp/q2same.out")
        wait_pending(queued, f"{SOCKET_DIR}/q2same.sock")
        time.sleep(3)
        assert pending_count(queued, f"{SOCKET_DIR}/q2same.sock") == 1
        queued.fail("grep -q '^exit=' /tmp/q2same.out")
        dialog_pid(queued, f"{SOCKET_DIR}/q2same.sock")
        answer(queued, "approve", f"{SOCKET_DIR}/q2same.sock", "once")
        client_ok(queued, "/tmp/q2same.out", "one-ok")
        queued.succeed("grep -q two-ok /tmp/q2same.out")
        assert queued.succeed(f"grep -F -c {SOCKET_DIR}/q2same.sock {DIALOG_LOG} || true").strip() == "1"

        # 2. A waiter that leaves does not take the others' prompts with it.
        # A second sandbox names the first one's session half a window later.
        # It is not part of that session, so it is asked on its own, not
        # joined to the first sandbox's prompt and not answered by it. The
        # first one's wait ends; the second one's prompt stays.
        session = "7f1d9a52-3c64-4d0b-9a7e-2b1c5e8f4a10"
        unix_client(queued, "q2shared", "first-ok", "/tmp/q2first.out", session)
        wait_pending(queued, f"{SOCKET_DIR}/q2shared.sock")
        time.sleep(10)
        unix_client(queued, "q2shared", "second-ok", "/tmp/q2second.out", session)
        time.sleep(3)
        assert pending_count(queued, f"{SOCKET_DIR}/q2shared.sock") == 2

        client_failed(queued, "/tmp/q2first.out")
        assert pending_count(queued, f"{SOCKET_DIR}/q2shared.sock") == 1
        queued.fail("grep -q '^exit=' /tmp/q2second.out")
        queued.succeed("! grep -q first-ok /tmp/q2first.out")
        dialog_pid(queued, f"{SOCKET_DIR}/q2shared.sock")
      '';

      node = "queued";
    };

    dialog = {
      body = ''
        # 4. An open dialog closes when its request is settled elsewhere, and
        # the next queued prompt takes its place.
        unix_client(queued, "q4first", "first-ok", "/tmp/q4first.out")
        wait_pending(queued, f"{SOCKET_DIR}/q4first.sock")
        first_dialog = dialog_pid(queued, f"{SOCKET_DIR}/q4first.sock")
        unix_client(queued, "q4second", "second-ok", "/tmp/q4second.out")
        wait_pending(queued, f"{SOCKET_DIR}/q4second.sock")
        queued.fail(f"grep -F -q {SOCKET_DIR}/q4second.sock {DIALOG_LOG}")

        answer(queued, "approve", f"{SOCKET_DIR}/q4first.sock", "project_package")
        queued.wait_until_fails(f"kill -0 {first_dialog}", timeout=15)
        client_ok(queued, "/tmp/q4first.out", "first-ok")

        second_dialog = dialog_pid(queued, f"{SOCKET_DIR}/q4second.sock")
        queued.succeed(f"kill -0 {second_dialog}")
        answer(queued, "deny", f"{SOCKET_DIR}/q4second.sock")
        queued.wait_until_fails(f"kill -0 {second_dialog}", timeout=15)
        client_failed(queued, "/tmp/q4second.out")
      '';

      node = "queued";
    };

    heartbeat = {
      body = ''
        # 3. Heartbeats keep a waiting client past its silence timeout. A, B and C
        # queue in one owner's line; C's own window opens only after A and B
        # expired. By then C's request is older than the 45 s the proxy tolerates
        # without hearing from policyd. It still pends exactly once, and its
        # client gets the answer.
        heartbeat.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
        heartbeat.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
        heartbeat.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
        heartbeat.wait_for_unit("agent-sandbox-policy.service")
        for port in [18085, 18086, 18087]:
            heartbeat.wait_for_unit(f"agent-sandbox-vm-tcp-{port}.service")

        def tcp_client(name, port):
            script = f"printf {name}-ok | socat -T 120 - TCP4:169.254.100.1:{port}; rc=$?; echo; echo exit=$rc"
            client_bg(heartbeat, "sandbox-queue-net-bash", script, f"/tmp/{name}.out")
            wait_pending(heartbeat, f"169.254.100.1:{port}")

        tcp_client("a", 18085)
        tcp_client("b", 18086)
        tcp_client("c", 18087)
        c_queued = time.monotonic()

        wait_settled(heartbeat, "169.254.100.1:18086", timeout=90)
        client_blocked(heartbeat, "/tmp/a.out", "a-ok")
        client_blocked(heartbeat, "/tmp/b.out", "b-ok")
        assert pending_count(heartbeat, "169.254.100.1:18087") == 1

        time.sleep(max(0, c_queued + 48 - time.monotonic()))
        assert pending_count(heartbeat, "169.254.100.1:18087") == 1
        heartbeat.fail("grep -q '^exit=' /tmp/c.out")
        answer(heartbeat, "approve", "169.254.100.1:18087", "once")
        client_ok(heartbeat, "/tmp/c.out", "c-ok")
        assert pending_count(heartbeat, "169.254.100.1:18087") == 0
      '';

      node = "heartbeat";
    };

    window = {
      body = ''
        # 1. A queued prompt keeps its full window. B queues behind the
        # unanswered A. B's own approval window opens when A is gone, so B is
        # still pending long after a window counted from its creation would have
        # run out, and its client then succeeds.
        unix_client(queued, "q1a", "a-ok", "/tmp/q1a.out")
        wait_pending(queued, f"{SOCKET_DIR}/q1a.sock")
        a_dialog = dialog_pid(queued, f"{SOCKET_DIR}/q1a.sock")
        queued.succeed(f"kill -0 {a_dialog}")

        unix_client(queued, "q1b", "b-ok", "/tmp/q1b.out")
        wait_pending(queued, f"{SOCKET_DIR}/q1b.sock")
        queued.fail(f"grep -F -q {SOCKET_DIR}/q1b.sock {DIALOG_LOG}")

        wait_settled(queued, f"{SOCKET_DIR}/q1a.sock", timeout=60)
        a_expired = time.monotonic()
        client_failed(queued, "/tmp/q1a.out")
        queued.wait_until_fails(f"kill -0 {a_dialog}", timeout=15)

        # B was queued a few seconds after A, so a window counted from its
        # creation ends about 4 s after A's. Waiting 9 s passes that point and
        # stays well inside the window that starts when A expires.
        time.sleep(max(0, a_expired + 9 - time.monotonic()))
        assert pending_count(queued, f"{SOCKET_DIR}/q1b.sock") == 1
        queued.fail("grep -q '^exit=' /tmp/q1b.out")
        dialog_pid(queued, f"{SOCKET_DIR}/q1b.sock")
        answer(queued, "approve", f"{SOCKET_DIR}/q1b.sock", "project_package")
        client_ok(queued, "/tmp/q1b.out", "b-ok")
      '';

      node = "queued";
    };
  };
  prelude = ''
    import shlex
    import time

    def command(*args):
        return shlex.join(str(arg) for arg in args)

    PENDING = "runuser -u sandbox -- agent-sandbox-approve pending"
    SOCKET_DIR = "/run/agent-sandbox-test"
    DIALOG_LOG = "/tmp/dialog-stub.log"

    def client_bg(node, package, script, out, session=None):
        # The wrapper records $PWD as the project root, so the client runs
        # from the sandbox user's home. Stdio is fully detached so the
        # driver's shell returns while the sandbox waits.
        env = ["XDG_RUNTIME_DIR=/run/user/1000"]
        if session is not None:
            env.append(f"AGENT_SANDBOX_SESSION_ID={session}")
        inner = f"cd /home/user && {shlex.join([package, '-c', script])}"
        detached = (
            f"nohup runuser -u sandbox -- env {shlex.join(env)} sh -c {shlex.quote(inner)} "
            f"</dev/null >{out} 2>&1 &"
        )
        node.succeed(command("sh", "-c", detached))

    def unix_client(node, name, payload, out, session=None):
        script = f"printf {payload} | socat -T 120 - UNIX-CONNECT:{SOCKET_DIR}/{name}.sock; rc=$?; echo; echo exit=$rc"
        client_bg(node, "sandbox-queue-bash", script, out, session)

    def pending_count(node, needle):
        return int(node.succeed(f"{PENDING} | grep -F -c {shlex.quote(needle)} || true").strip())

    def wait_pending(node, needle, timeout=60):
        node.wait_until_succeeds(f"{PENDING} | grep -F -q {shlex.quote(needle)}", timeout=timeout)

    def wait_settled(node, needle, timeout):
        node.wait_until_succeeds(f"! {PENDING} | grep -F -q {shlex.quote(needle)}", timeout=timeout)

    def pending_id(node, needle):
        return node.succeed(f"{PENDING} | grep -F {shlex.quote(needle)} | head -1").split("\t")[0]

    def answer(node, verb, needle, *scope):
        node.succeed(
            command("runuser", "-u", "sandbox", "--", "agent-sandbox-approve", verb, pending_id(node, needle), *scope)
        )

    def dialog_pid(node, needle):
        node.wait_until_succeeds(f"grep -F -q {shlex.quote(needle)} {DIALOG_LOG}", timeout=30)
        line = node.succeed(f"grep -F {shlex.quote(needle)} {DIALOG_LOG} | head -1")
        return int(line.split()[0])

    def client_failed(node, out):
        node.wait_until_succeeds(f"grep -q '^exit=' {out}", timeout=30)
        node.fail(f"grep -q '^exit=0' {out}")

    def client_blocked(node, out, payload):
        # The proxy closes a blocked connection cleanly, so the client exits
        # 0 without the echo.
        node.wait_until_succeeds(f"grep -q '^exit=' {out}", timeout=30)
        node.fail(f"grep -q {payload} {out}")

    def client_ok(node, out, payload):
        try:
            node.wait_until_succeeds(f"grep -q '^exit=0' {out}", timeout=30)
        except Exception:
            print(node.execute(f"echo OUT; cat {out}; echo PENDING; {PENDING}")[1])
            raise
        node.succeed(f"grep -q {payload} {out}")
  '';
  # Resource prompts: queueing, coalesced waiters and dialog lifecycle.
  queuedNode =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate uiConfig (
        lib.recursiveUpdate (installPolicy resourceApprovalPolicy) {
          imports = [ module ];

          agent-sandbox = {
            enable = true;

            gates = {
              filesystem.enable = true;
              resources.enable = true;
            };

            packages = [
              (mkBash "sandbox-queue-bash" {
                extraPkgs = commonExtraPkgs ++ [ pkgs.python3 ];
              })
            ];

            policy.dbus.enable = false;
          };

          services.dbus.enable = true;

          systemd.services.agent-sandbox-vm-queue-sockets = {
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = "${unixSocketServers}";
              Restart = "on-failure";
              RuntimeDirectory = "agent-sandbox-test";
              User = "sandbox";
            };
          };
        }
      )
    );
  tcpPorts = [
    18085
    18086
    18087
  ];
  # policyd auto-spawns the real agent-sandbox-ui for each sandbox session;
  # only its dialog helper is replaced.
  uiConfig = {
    agent-sandbox.policy = {
      inherit approvalTimeout;
      uiBackend = "qt-dialog";
    };

    systemd.services.agent-sandbox-policy.environment.AGENT_SANDBOX_QT_DIALOG = "${dialogStub}";
  };
  unixSocketServers = pkgs.writeShellScript "agent-sandbox-vm-queue-sockets" ''
    for name in ${lib.concatStringsSep " " unixSockets}; do
      ${pkgs.socat}/bin/socat UNIX-LISTEN:/run/agent-sandbox-test/$name.sock,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat &
    done
    wait
  '';
  unixSockets = [
    "q1a"
    "q1b"
    "q2shared"
    "q2same"
    "q4first"
    "q4second"
  ];
in
name: partNames:
let
  node = parts.${builtins.head partNames}.node;
  sameNode = builtins.all (part: parts.${part}.node == node) partNames;
in
assert lib.assertMsg sameNode "approval-queue group ${name} mixes nodes";
pkgs.testers.runNixOSTest (_: {
  name = "e2e-approval-queue-${name}";
  node.specialArgs = { inherit inputs; };
  nodes.${node} = nodeConfigs.${node};
  testScript =
    prelude + setups.${node} + lib.concatMapStringsSep "\n" (part: parts.${part}.body) partNames;
})
