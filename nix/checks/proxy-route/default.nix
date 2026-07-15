{ pkgs, ... }:
pkgs.runCommand "proxy-route-regression"
  {
    nativeBuildInputs = [
      pkgs.bash
      pkgs.coreutils
    ];
  }
  ''
    set -euo pipefail
    fail() { echo "FAIL: $*" >&2; exit 1; }

    eval "$(sed -n '/^fresh_handshake()/,/^}/p' ${../../modules/nixos/agent-sandbox/proxy-route.sh})"

    fresh_handshake 1700000000 1700000000 || fail "same-second handshake was rejected"
    fresh_handshake 1700000001 1700000000 || fail "later handshake was rejected"
    if fresh_handshake 1699999999 1700000000; then
      fail "older handshake was accepted"
    fi
    if fresh_handshake invalid 1700000000; then
      fail "non-numeric handshake was accepted"
    fi

    touch "$out"
  ''
