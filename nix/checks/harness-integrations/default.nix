{ pkgs, inputs, ... }:

let
  codexPkg = flake.package "codex-desktop";
  contract = import ../../lib/harness-integrations.nix;
  disabled = mkSystem { };
  enabled = mkSystem { agent-sandbox.dynamicProjectAttribution.enable = true; };
  enabledPackages = map (package: package.name) enabled.config.agent-sandbox.packages;
  flake = import ../../lib/consumer.nix { inherit inputs pkgs; };
  harnessPkg = flake.package "harness-integrations";
  lib = inputs.nixpkgs.lib;
  mkSystem =
    extraModule:
    lib.nixosSystem {
      inherit system;

      modules = [
        module
        {
          nixpkgs.pkgs = pkgs;
          system.stateVersion = "26.11";
        }
        extraModule
      ];

      specialArgs = { inherit inputs; };
    };
  module = ../../modules/nixos/agent-sandbox;
  sandboxPkg = flake.package "agent-sandbox";
  system = pkgs.stdenv.hostPlatform.system;
  variables = enabled.config.environment.sessionVariables;
  dshPkg = flake.package "dsh";
in
assert contract.protocolMajor == 1;
assert contract.executables.contextAdapter == "agent-sandbox-context-adapter";
assert contract.executables.stoppedChild == "agent-sandbox-child";
assert contract.executables.proxy == "agent-sandbox-proxy";
assert contract.executables.dbusBridge == "agent-sandbox-dbus-proxy";
assert contract.dsh.version == "0.1.1-rc.2";
assert contract.dsh.gitCommit == "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e";
assert contract.codex.desktop.version == "26.825.51511";
assert contract.codex.runtime.version == "0.151.0-alpha.7.2";
assert contract.codex.appServer.transport == "stdio-jsonl";
assert contract.codex.appServer.sharedSocket == false;
assert !contract.codex.desktop.electronAsarPatch;
assert !disabled.config.agent-sandbox.dynamicProjectAttribution.enable;
assert !(disabled.config.environment.sessionVariables ? AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL);
assert enabled.config.agent-sandbox.enable;
assert enabled.config.agent-sandbox.gates.filesystem.enable;
assert enabled.config.agent-sandbox.gates.resources.enable;
assert enabled.config.agent-sandbox.gates.syscalls.enable;
assert enabled.config.agent-sandbox.network.enable;
assert enabled.config.agent-sandbox.network.httpProxy.enable;
assert enabled.config.agent-sandbox.policy.dbus.enable;
assert enabled.config.agent-sandbox.sudoPolicy == "approve";
assert lib.elem "dsh" enabledPackages;
assert lib.elem "codex-desktop" enabledPackages;
assert variables.AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL == "1";
assert variables.AGENT_SANDBOX_CONTEXT_ADAPTER_REQUIRED == "1";
assert variables.AGENT_SANDBOX_CONTEXT_ADAPTER == "${harnessPkg}/bin/agent-sandbox-context-adapter";
assert variables.AGENT_SANDBOX_CHILD == "${harnessPkg}/bin/agent-sandbox-child";
assert variables.AGENT_SANDBOX_PROXY == "${sandboxPkg}/bin/agent-sandbox-proxy";
assert variables.AGENT_SANDBOX_DBUS_PROXY == "${sandboxPkg}/bin/agent-sandbox-dbus-proxy";
assert variables.CODEX_APP_SERVER_TRANSPORT == "stdio-jsonl";
assert variables.CODEX_APP_SERVER_SHARED_SOCKET == "0";
pkgs.runCommand "harness-integrations" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    set -euo pipefail
    for executable in agent-sandbox-context-adapter agent-sandbox-child agent-sandbox-proxy agent-sandbox-dbus-proxy; do
      test -x "${harnessPkg}/bin/$executable"
    done
    test "$(readlink -e ${harnessPkg}/bin/agent-sandbox-proxy)" = "${sandboxPkg}/bin/agent-sandbox-proxy"
    test "$(readlink -e ${harnessPkg}/bin/agent-sandbox-dbus-proxy)" = "${sandboxPkg}/bin/agent-sandbox-dbus-proxy"
    ${harnessPkg}/bin/agent-sandbox-context-adapter --version | grep -Fx 'agent-sandbox-context-adapter protocol 1'
    if ${harnessPkg}/bin/agent-sandbox-child >/dev/null 2>&1; then
      exit 1
    else
      test $? -eq 64
    fi
    ${sandboxPkg}/bin/agent-sandbox-proxy --help >/dev/null
    ${sandboxPkg}/bin/agent-sandbox-dbus-proxy --help >/dev/null
    grep -F "${harnessPkg}/bin/agent-sandbox-context-adapter" ${dshPkg}/bin/dsh
    grep -F "${harnessPkg}/bin/agent-sandbox-context-adapter" ${codexPkg}/bin/codex
    ${dshPkg}/bin/dsh --version | grep -F '0.1.1-rc.2'
    ${codexPkg}/bin/codex --version | grep -F '0.151.0-alpha.7.2'
    ADAPTER=${harnessPkg}/bin/agent-sandbox-context-adapter CHILD=${harnessPkg}/bin/agent-sandbox-child ${pkgs.python3}/bin/python3 - <<'PYTHON'
  import json
  import os
  import signal
  import socket
  import subprocess
  import time

  adapter = os.environ["ADAPTER"]
  child = os.environ["CHILD"]

  def line(channel):
      result = bytearray()
      while not result.endswith(b"\n"):
          part = channel.recv(4096)
          assert part
          result.extend(part)
      return json.loads(result)

  client, server = socket.socketpair()
  env = os.environ.copy()
  env.update(
      AGENT_SANDBOX_CONTEXT_ADAPTER_FD=str(client.fileno()),
      AGENT_SANDBOX_SESSION_ID="check-session",
  )
  registered = subprocess.Popen(
      [adapter, "--", "sh", "-c", "test \"$AGENT_SANDBOX_CONTEXT_ADAPTER_REGISTERED\" = 1"],
      env=env,
      pass_fds=(client.fileno(),),
  )
  client.close()
  request = line(server)
  assert request == {
      "operation": "register_context_adapter",
      "request_id": 1,
      "protocol_major": 1,
      "sandbox_session_id": "check-session",
  }
  server.sendall(b"{\"message\":\"registered\",\"request_id\":1,\"protocol_major\":1}\n")
  assert registered.wait(timeout=5) == 0
  server.close()

  client, server = socket.socketpair()
  ready_read, ready_write = os.pipe()
  env = os.environ.copy()
  env["AGENT_SANDBOX_CONTEXT_ADAPTER_FD"] = str(client.fileno())
  env["AGENT_SANDBOX_CHILD_READY_FD"] = str(ready_write)
  wrapped = subprocess.Popen(
      [child, "--", "sh", "-c", "test -z \"$AGENT_SANDBOX_CONTEXT_ADAPTER_FD\"; printf child-ok"],
      env=env,
      pass_fds=(client.fileno(), ready_write),
      stdout=subprocess.PIPE,
  )
  client.close()
  os.close(ready_write)
  pid = int(os.read(ready_read, 64))
  os.close(ready_read)
  for _ in range(50):
      with open(f"/proc/{pid}/status") as status:
          if any(line.startswith("State:") and "T" in line for line in status):
              break
      time.sleep(0.01)
  else:
      raise AssertionError("child did not stop before exec")
  os.kill(pid, signal.SIGCONT)
  assert wrapped.communicate(timeout=5)[0] == b"child-ok"
  server.close()
  PYTHON
    touch $out
''
