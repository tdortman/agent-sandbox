#!/usr/bin/env bash
set -euo pipefail

action="$1"
marker="$2"

write_marker() {
  [[ "${INVOCATION_ID:-}" =~ ^[0-9a-f]{32}$ ]] || {
    echo "agent-sandbox readiness: invalid systemd invocation ID" >&2
    exit 1
  }
  temporary="$(mktemp "${marker}.tmp.XXXXXX")"
  trap 'rm -f "$temporary"' EXIT
  printf '%s\n' "$INVOCATION_ID" > "$temporary"
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$marker"
  trap - EXIT
}

case "$action" in
  create)
    write_marker
    ;;
  create-listener)
    port="$3"
    rm -f -- "$marker"
    for _attempt in $(seq 1 60); do
      if ss -H -lun | grep -Eq ":${port}[[:space:]]"; then
        write_marker
        exit 0
      fi
      sleep 0.5
    done
    echo "agent-sandbox readiness: WireGuard listener did not bind" >&2
    exit 1
    ;;
  remove)
    rm -f -- "$marker"
    ;;
  *)
    echo "usage: readiness-marker (create|create-listener|remove) PATH [PORT]" >&2
    exit 2
    ;;
esac
