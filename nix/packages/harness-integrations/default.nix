{ lib, pkgs, ... }:

let
  contract = import ../../lib/harness-integrations.nix;
  contractJson = pkgs.writeText "agent-sandbox-harness-integrations.json" (builtins.toJSON contract);
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "agent-sandbox-harness-integrations";
  version = "1";

  installPhase = ''
    runHook preInstall
    install -Dm0644 ${contractJson} "$out/share/agent-sandbox/harness-integrations.json"

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
    export AGENT_SANDBOX_CONTEXT_ADAPTER="agent-sandbox"
    export AGENT_SANDBOX_CHILD="agent-sandbox-child"
    exec "''${DSH_CLI_PATH:-dsh}" "$@"
    DSH

    install -Dm0755 /dev/stdin "$out/bin/codex-agent-sandbox" <<'CODEX'
    #!/usr/bin/env bash
    set -euo pipefail
    export AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL=1
    export AGENT_SANDBOX_CONTEXT_ADAPTER="agent-sandbox"
    export AGENT_SANDBOX_CHILD="agent-sandbox-child"
    if [[ "''${1:-}" == "app-server" ]]; then
      export CODEX_APP_SERVER_TRANSPORT="stdio-jsonl"
      export CODEX_APP_SERVER_SHARED_SOCKET=0
      unset CODEX_APP_SERVER_SOCKET CODEX_APP_SERVER_LISTEN
    fi
    exec "''${CODEX_CLI_PATH:-codex}" "$@"
    CODEX
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
