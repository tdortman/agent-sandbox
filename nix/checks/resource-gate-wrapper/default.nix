# Build-time regression guard for resource-gate dynamic wrapper generation.
#
# Asserts that the resource-gate wrapper produces the correct bwrap
# argument shape: host /run visible (no broad --tmpfs /run), but
# /run/agent-sandbox masked, /dev left visible via --dev-bind /dev /dev
# (opened through the syscall broker, not hidden behind tmpfs), GPU/device-path
# binds suppressed, and the sandbox policy socket re-bound read-only.
#
# Also asserts that a non-resource-gate wrapper preserves the current
# behavior: broad --tmpfs /run, GPU auto-binds, and devicePaths.
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

  resourceGateWrapper = agentSandboxLib.mkWrapPackage pkgs {
    package = pkgs.hello;
    binary = "hello";
    fsArmPkg = pkgs.hello;
    syscallArmPkg = pkgs.hello;
    policyContext = true;
    resourceGate = true;
    devicePaths = [ "/dev/agent-sandbox-regression-device" ];
    policySocket = "/tmp/resource-gate-regression.sock";
    sandboxPolicySocket = "/tmp/resource-gate-regression-sandbox.sock";
  };

  nonResourceGateWrapper = agentSandboxLib.mkWrapPackage pkgs {
    package = pkgs.hello;
    binary = "hello";
    fsArmPkg = pkgs.hello;
    policyContext = true;
    devicePaths = [ "/dev/agent-sandbox-regression-device" ];
    policySocket = "/tmp/resource-gate-regression.sock";
    sandboxPolicySocket = "/tmp/resource-gate-regression-sandbox.sock";
  };
in
pkgs.runCommand "resource-gate-wrapper-regression" { } ''
  fail() { echo "FAIL: $*" >&2; exit 1; }

  RG_SCRIPT=$(readlink -f ${resourceGateWrapper}/bin/hello)
  [[ -n "$RG_SCRIPT" && -f "$RG_SCRIPT" ]] || fail "resource-gate wrapped script not found"
  cp "$RG_SCRIPT" rg-wrapper.sh

  NRG_SCRIPT=$(readlink -f ${nonResourceGateWrapper}/bin/hello)
  [[ -n "$NRG_SCRIPT" && -f "$NRG_SCRIPT" ]] || fail "non-resource-gate wrapped script not found"
  cp "$NRG_SCRIPT" nrg-wrapper.sh

  # --- Resource-gate mode assertions ---

  # 1. Host root is bind-mounted.
  grep -F -q -- '--bind / /' rg-wrapper.sh \
    || fail "resource-gate: missing --bind / /"

  # 2. /run/agent-sandbox is masked with tmpfs (not broad /run).
  grep -F -q -- '--tmpfs /run/agent-sandbox' rg-wrapper.sh \
    || fail "resource-gate: missing --tmpfs /run/agent-sandbox"

  # 3. Broad --tmpfs /run is NOT present in resource-gate mode.
  if grep -F -q -- 'RUNTIME_ARGS+=(--tmpfs /run)' rg-wrapper.sh; then
    fail "resource-gate: broad --tmpfs /run should not be present"
  fi

  # 4. /dev stays visible (broker gates opens); not hidden behind tmpfs.
  grep -F -q -- '--dev-bind /dev /dev' rg-wrapper.sh \
    || fail "resource-gate: missing --dev-bind /dev /dev"
  if grep -F -q -- '--tmpfs /dev' rg-wrapper.sh; then
    fail "resource-gate: /dev must not be tmpfs-masked (broker gates device access)"
  fi

  # 5. /proc is sandbox-private.
  grep -F -q -- '--proc /proc' rg-wrapper.sh \
    || fail "resource-gate: missing --proc /proc"

  # 6. GPU auto-bind loop is suppressed.
  if grep -F -q 'for _gpu in /dev/nvidia' rg-wrapper.sh; then
    fail "resource-gate: GPU auto-bind loop should be suppressed"
  fi

  # 7. Configured devicePaths are suppressed in resource-gate mode.
  if grep -F -q 'agent-sandbox-regression-device' rg-wrapper.sh; then
    fail "resource-gate: configured devicePaths should be suppressed"
  fi

  # 8. Sandbox policy socket is re-bound read-only.
  grep -F -q -- '--ro-bind-try /tmp/resource-gate-regression-sandbox.sock' rg-wrapper.sh \
    || fail "resource-gate: missing sandbox policy socket ro-bind-try"

  # --- Non-resource-gate mode assertions ---

  # 9. Broad --tmpfs /run IS present in non-resource-gate mode.
  grep -F -q -- 'RUNTIME_ARGS+=(--tmpfs /run)' nrg-wrapper.sh \
    || fail "non-resource-gate: missing broad --tmpfs /run"

  # 10. GPU auto-bind loop IS present in non-resource-gate mode.
  grep -F -q 'for _gpu in /dev/nvidia' nrg-wrapper.sh \
    || fail "non-resource-gate: GPU auto-bind loop should be present"

  # 11. Configured devicePaths ARE present in non-resource-gate mode.
  grep -F -q 'agent-sandbox-regression-device' nrg-wrapper.sh \
    || fail "non-resource-gate: configured devicePaths should be present"

  echo "PASS: resource-gate wrapper regression guard satisfied"
  touch $out
''
