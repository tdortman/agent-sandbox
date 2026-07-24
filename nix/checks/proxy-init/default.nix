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
      pkgs.openssl
    ];

    text = builtins.readFile ../../modules/nixos/agent-sandbox/proxy-init.sh;
  };
in
pkgs.runCommand "proxy-init-regression"
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.openssl
    ];
  }
  ''
    set -euo pipefail

    fail() { echo "FAIL: $*" >&2; exit 1; }

    state="$TMPDIR/state"
    bundle="$TMPDIR/bundle.pem"
    host_bundle="$TMPDIR/host-bundle.pem"
    printf '%s\n' 'host trust placeholder' > "$host_bundle"

    ${proxyInit}/bin/proxy-init-regression "$state" "$bundle" "$host_bundle"

    [[ ! -e "$state/proxy-ca.pem" ]] || fail "obsolete combined CA file was generated"
    [[ -s "$state/proxy-ca-cert.pem" ]] || fail "certificate-only CA file is missing"
    [[ -s "$state/proxy-ca.key" ]] || fail "CA private key is missing"
    [[ ! -e "$state/proxy-ca-dhparam.pem" ]] || fail "unused DH parameters were generated"

    openssl pkey -in "$state/proxy-ca.key" -noout
    openssl x509 -in "$state/proxy-ca-cert.pem" -noout

    if grep -F -q -- 'PRIVATE KEY' "$bundle"; then
      fail "CA bundle contains a private key"
    fi

    grep -F -q -- 'host trust placeholder' "$bundle" || fail "host trust was not preserved"
    grep -F -q -- 'BEGIN CERTIFICATE' "$bundle" || fail "proxy CA was not added to the bundle"

    rm -- "$bundle"
    ${proxyInit}/bin/proxy-init-regression "$state" "$bundle" "$host_bundle"
    openssl pkey -in "$state/proxy-ca.key" -noout
    openssl x509 -in "$state/proxy-ca-cert.pem" -noout

    touch "$out"
  ''
