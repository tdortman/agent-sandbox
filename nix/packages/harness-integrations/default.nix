{ lib, pkgs, ... }:

let
  contract = import ../../lib/harness-integrations.nix;
  contractJson = pkgs.writeText "agent-sandbox-harness-integrations.json" (builtins.toJSON contract);
  sandboxPkg = pkgs.agent-sandbox.agent-sandbox;
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "agent-sandbox-harness-integrations";
  version = "1";

  installPhase = ''
    runHook preInstall
    install -Dm0644 ${contractJson} "$out/share/agent-sandbox/harness-integrations.json"
    mkdir -p "$out/bin" "$out/libexec"

    ln -s ${sandboxPkg}/bin/agent-sandbox-proxy "$out/bin/agent-sandbox-proxy"
    ln -s ${sandboxPkg}/bin/agent-sandbox-dbus-proxy "$out/bin/agent-sandbox-dbus-proxy"

    install -Dm0755 /dev/stdin "$out/bin/agent-sandbox-context-adapter" <<'ADAPTER'
    #!${pkgs.bash}/bin/bash
    exec ${pkgs.python3}/bin/python3 "@out@/libexec/agent-sandbox-context-adapter.py" "$@"
    ADAPTER
    substituteInPlace "$out/bin/agent-sandbox-context-adapter" --replace-fail @out@ "$out"
    install -Dm0755 /dev/stdin "$out/libexec/agent-sandbox-context-adapter.py" <<'PYTHON'
    import json
    import os
    import socket
    import sys

    EXIT_USAGE = 64
    EXIT_UNAVAILABLE = 78

    def fail(message, code=EXIT_UNAVAILABLE):
        print(f"agent-sandbox-context-adapter: {message}", file=sys.stderr)
        raise SystemExit(code)

    args = sys.argv[1:]
    if args[:1] == ["--version"]:
        print("agent-sandbox-context-adapter protocol 1")
        raise SystemExit(0)
    if args[:1] in (["--help"], ["-h"]):
        print("usage: agent-sandbox-context-adapter -- command [args...]")
        raise SystemExit(0)
    if args[:1] == ["--"]:
        args = args[1:]
    if not args:
        fail("an executable is required", EXIT_USAGE)

    fd_text = os.environ.get("AGENT_SANDBOX_CONTEXT_ADAPTER_FD", "")
    if not fd_text.isdigit():
        if os.environ.get("AGENT_SANDBOX_CONTEXT_ADAPTER_REQUIRED") == "1":
            fail("missing inherited adapter fd")
        os.execvpe(args[0], args, os.environ)

    fd = int(fd_text)
    try:
        os.fstat(fd)
    except OSError as error:
        fail(f"adapter fd is not open: {error}")

    os.set_inheritable(fd, True)
    if os.environ.get("AGENT_SANDBOX_CONTEXT_ADAPTER_REGISTERED") != "1":
        session_id = os.environ.get("AGENT_SANDBOX_SESSION_ID", "")
        if not session_id:
            fail("missing sandbox session id")
        request = {
            "operation": "register_context_adapter",
            "request_id": 1,
            "protocol_major": 1,
            "sandbox_session_id": session_id,
        }
        try:
            channel = socket.socket(fileno=fd)
            channel.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
            reply = bytearray()
            while not reply.endswith(b"\n"):
                chunk = channel.recv(4096)
                if not chunk:
                    fail("adapter connection closed during registration")
                reply.extend(chunk)
                if len(reply) > 1024 * 1024:
                    fail("adapter registration reply is too large")
            message = json.loads(reply)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            fail(f"adapter registration failed: {error}")
        if (
            not isinstance(message, dict)
            or message.get("message") != "registered"
            or message.get("request_id") != 1
            or message.get("protocol_major") != 1
        ):
            fail("adapter registration was rejected")
        os.environ["AGENT_SANDBOX_CONTEXT_ADAPTER_REGISTERED"] = "1"

    os.environ["AGENT_SANDBOX_CONTEXT_ADAPTER_FD"] = str(fd)
    os.execvpe(args[0], args, os.environ)
    PYTHON

    install -Dm0755 /dev/stdin "$out/bin/agent-sandbox-child" <<'CHILD'
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ''${1:-} == "--contract" ]]; then
      cat "${contractJson}"
      exit 0
    fi
    if [[ ''${1:-} == "--" ]]; then
      shift
    fi
    if (( $# == 0 )); then
      printf '%s\n' "agent-sandbox-child: an executable is required" >&2
      exit 64
    fi
    adapter_fd=''${AGENT_SANDBOX_CONTEXT_ADAPTER_FD:-}
    if [[ ! $adapter_fd =~ ^[0-9]+$ ]]; then
      printf '%s\n' "agent-sandbox-child: missing inherited adapter fd" >&2
      exit 78
    fi
    if ! { : >&"$adapter_fd"; } 2>/dev/null; then
      printf '%s\n' "agent-sandbox-child: adapter fd is not open" >&2
      exit 78
    fi
    # The stopped wrapper proves the parent has an authenticated adapter, but
    # the untrusted child must never inherit that descriptor.
    eval "exec $adapter_fd>&-"
    unset AGENT_SANDBOX_CONTEXT_ADAPTER_FD AGENT_SANDBOX_CONTEXT_ADAPTER_REGISTERED
    ready_fd=''${AGENT_SANDBOX_CHILD_READY_FD:-}
    if [[ -n $ready_fd ]]; then
      if [[ ! $ready_fd =~ ^[0-9]+$ ]]; then
        printf '%s\n' "agent-sandbox-child: invalid ready fd" >&2
        exit 78
      fi
      printf '%s\n' "$$" >&"$ready_fd"
    fi
    # The trusted parent sends exactly one pidfd attach_process request before
    # resuming this process. No untrusted command runs before SIGCONT.
    kill -STOP "$$"
    exec "$@"
    CHILD

    install -Dm0755 /dev/stdin "$out/bin/dsh-agent-sandbox" <<'DSH'
    #!/usr/bin/env bash
    set -euo pipefail
    export AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL=1
    export AGENT_SANDBOX_CONTEXT_ADAPTER="@out@/bin/agent-sandbox-context-adapter"
    export AGENT_SANDBOX_CHILD="@out@/bin/agent-sandbox-child"
    export AGENT_SANDBOX_PROXY="@out@/bin/agent-sandbox-proxy"
    export AGENT_SANDBOX_DBUS_PROXY="@out@/bin/agent-sandbox-dbus-proxy"
    exec "@out@/bin/agent-sandbox-context-adapter" -- "''${DSH_CLI_PATH:-dsh}" "$@"
    DSH
    substituteInPlace "$out/bin/dsh-agent-sandbox" --replace-fail @out@ "$out"

    install -Dm0755 /dev/stdin "$out/bin/codex-agent-sandbox" <<'CODEX'
    #!/usr/bin/env bash
    set -euo pipefail
    export AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL=1
    export AGENT_SANDBOX_CONTEXT_ADAPTER="@out@/bin/agent-sandbox-context-adapter"
    export AGENT_SANDBOX_CHILD="@out@/bin/agent-sandbox-child"
    export AGENT_SANDBOX_PROXY="@out@/bin/agent-sandbox-proxy"
    export AGENT_SANDBOX_DBUS_PROXY="@out@/bin/agent-sandbox-dbus-proxy"
    if [[ "''${1:-}" == "app-server" ]]; then
      export CODEX_APP_SERVER_TRANSPORT="stdio-jsonl"
      export CODEX_APP_SERVER_SHARED_SOCKET=0
      unset CODEX_APP_SERVER_SOCKET CODEX_APP_SERVER_LISTEN
    fi
    exec "@out@/bin/agent-sandbox-context-adapter" -- "''${CODEX_CLI_PATH:-codex}" "$@"
    CODEX
    substituteInPlace "$out/bin/codex-agent-sandbox" --replace-fail @out@ "$out"
    runHook postInstall
  '';

  dontUnpack = true;
  passthru.contract = contract;

  meta = {
    description = "Context adapter launch seams for DSH and Codex";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
