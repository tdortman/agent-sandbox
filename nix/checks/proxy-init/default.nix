{
  pkgs,
  ...
}:
let
  echInit = pkgs.writeShellApplication {
    name = "proxy-ech-init-regression";
    runtimeInputs = [ pkgs.coreutils ];

    text = ''
      set -euo pipefail
      [[ "$#" == 3 ]] || exit 1
      [[ "$1" == "--init-ech-state-only" ]] || exit 1
      [[ "$2" == "--ech-state-dir" ]] || exit 1
      state="$3"
      mkdir -p "$state"
      printf '%s\n' "$*" >> "$state/ech-init-args"
      : > "$state/ech-config-list"
    '';
  };
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

    ${proxyInit}/bin/proxy-init-regression "$state" "$bundle" "$host_bundle" ${echInit}/bin/proxy-ech-init-regression
    grep -F -q -- '--init-ech-state-only --ech-state-dir' "$state/ech-init-args" \
      || fail "ECH state initialization was not ordered through proxy init"

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
    ${proxyInit}/bin/proxy-init-regression "$state" "$bundle" "$host_bundle" ${echInit}/bin/proxy-ech-init-regression
    openssl pkey -in "$state/proxy-ca.key" -noout
    openssl x509 -in "$state/proxy-ca-cert.pem" -noout

    touch "$out"
  ''
