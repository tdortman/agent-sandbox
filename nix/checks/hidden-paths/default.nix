# Regression guard for dynamic-FS hidden path masking.
#
# Dynamic wrappers bind the host root (`--bind / /`). `hiddenPaths` overlays
# selected paths afterward so the sandbox cannot see them (tmpfs for dirs,
# /dev/null for files). Default includes ~/.snapshots.
{
  pkgs,
  lib,
  inputs,
  ...
}:
let
  agentSandboxLib = import ../../modules/nixos/agent-sandbox/lib.nix {
    inherit lib;
    inherit (inputs) jail-nix;
  };

  sampleWrapper = agentSandboxLib.mkWrapPackage pkgs {
    package = pkgs.hello;
    binary = "hello";
    fsArmPkg = pkgs.hello;
    hiddenPaths = [
      "~/.snapshots"
      "/secret/file"
    ];
  };
in
pkgs.runCommand "hidden-paths-regression" { } ''
  fail() { echo "FAIL: $*" >&2; exit 1; }

  SCRIPT=$(readlink -f ${sampleWrapper}/bin/hello)
  [[ -n "$SCRIPT" && -f "$SCRIPT" ]] || fail "wrapped script not found"
  cp "$SCRIPT" wrapper.sh

  grep -F -q '_asbx_hide=' wrapper.sh \
    || fail "hidden path expansion block missing"

  grep -F -q '_asbx_hide="$HOME/.snapshots"' wrapper.sh \
    || fail "~/.snapshots must expand to \$HOME/.snapshots at generation time"

  grep -F -q 'RUNTIME_ARGS+=(--tmpfs "$_asbx_hide")' wrapper.sh \
    || fail "directory hide must use --tmpfs"

  grep -F -q 'RUNTIME_ARGS+=(--ro-bind /dev/null "$_asbx_hide")' wrapper.sh \
    || fail "file hide must bind /dev/null"

  # hidePathsScript must run after the broad host bind (via RUNTIME_ARGS tail).
  grep -F -q -- '--bind / /' wrapper.sh \
    || fail "dynamic wrapper must bind host root"

  echo "PASS: hidden path masking regression guard satisfied"
  touch $out
''
