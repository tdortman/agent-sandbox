{
  pkgs,
  ...
}:
let
  proxyInit = pkgs.writeShellApplication {
    name = "proxy-init-regression";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.jq
      pkgs.openssl
      pkgs.wireguard-tools
    ];
    text = builtins.readFile ../../modules/nixos/agent-sandbox/proxy-init.sh;
  };
  mitmproxyPolicyTests = pkgs.runCommand "mitmproxy-policy-regression-test" { } ''
    mkdir -p "$out"
    cp ${../../packages/agent-sandbox/mitmproxy/mitmproxy-policy.py} "$out/mitmproxy-policy.py"
    cp ${../../packages/agent-sandbox/mitmproxy/test-mitmproxy-policy.py} "$out/test-mitmproxy-policy.py"
  '';
  inherit (pkgs) mitmproxy;
in
pkgs.runCommand "proxy-init-regression"
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.openssl
      mitmproxy
      pkgs.python3Packages.python
      pkgs.wireguard-tools
    ];
  }
  ''
    set -euo pipefail

    check_mitmproxy_startup() {
      local log="$1"
      set +e
      timeout 3 mitmdump \
        --mode wireguard@51820 \
        --set "confdir=$state" \
        --no-server >"$log" 2>&1
      local status=$?
      set -e
      if [[ "$status" != 0 && "$status" != 124 ]]; then
        cat "$log" >&2
        fail "mitmproxy failed while loading the CA store"
      fi
      if grep -E -q 'Valid PEM|BEGIN/END delimiters|Traceback' "$log"; then
        cat "$log" >&2
        fail "mitmproxy reported a CA-store startup error"
      fi
    }
    fail() { echo "FAIL: $*" >&2; exit 1; }
    state="$TMPDIR/state"
    bundle="$TMPDIR/bundle.pem"
    host_bundle="$TMPDIR/host-bundle.pem"
    printf '%s\n' 'host trust placeholder' > "$host_bundle"

    ${proxyInit}/bin/proxy-init-regression "$state" "$bundle" "$host_bundle"

    [[ -s "$state/mitmproxy-ca.pem" ]] || fail "combined CA file is missing"
    [[ -s "$state/mitmproxy-ca-cert.pem" ]] || fail "certificate-only CA file is missing"
    [[ -s "$state/mitmproxy-ca.key" ]] || fail "CA private key is missing"
    [[ -s "$state/mitmproxy-ca-dhparam.pem" ]] || fail "DH parameters are missing"
    openssl pkey -in "$state/mitmproxy-ca.pem" -noout
    openssl x509 -in "$state/mitmproxy-ca.pem" -noout
    openssl dhparam -in "$state/mitmproxy-ca-dhparam.pem" -check -noout
    if grep -F -q -- 'PRIVATE KEY' "$bundle"; then
      fail "CA bundle contains a private key"
    fi
    old_public="$({ openssl x509 -in "$state/mitmproxy-ca-cert.pem" -pubkey -noout || exit 1; } | openssl pkey -pubin -outform DER | sha256sum)"
    check_mitmproxy_startup "$TMPDIR/initial-startup.log"
    python ${mitmproxyPolicyTests}/test-mitmproxy-policy.py

    # Recreate the old state layout: mitmproxy-ca.pem held only the cert,
    # while mitmproxy-ca.key held the private key separately.
    cp -- "$state/mitmproxy-ca-cert.pem" "$state/mitmproxy-ca.pem"
    rm -- "$state/mitmproxy-ca-cert.pem"
    ${proxyInit}/bin/proxy-init-regression "$state" "$bundle" "$host_bundle"

    openssl pkey -in "$state/mitmproxy-ca.pem" -noout
    new_public="$({ openssl x509 -in "$state/mitmproxy-ca-cert.pem" -pubkey -noout || exit 1; } | openssl pkey -pubin -outform DER | sha256sum)"
    [[ "$old_public" == "$new_public" ]] || fail "legacy CA migration rotated the key"
    if grep -F -q -- 'PRIVATE KEY' "$bundle"; then
      fail "migrated CA bundle contains a private key"
    fi
    check_mitmproxy_startup "$TMPDIR/migrated-startup.log"

    touch "$out"
  ''
