# Regression guard for ~/.config/agent-sandbox policy-symlink protection.
#
# The dynamic-FS wrapper bind-mounts the host root with `--bind / /`, which
# makes the user's $HOME (including ~/.config/agent-sandbox) fully writable
# inside the sandbox. Rebinding the logical config directory read-only is
# not sufficient: a symlinked policy.json points outside that directory
# (typically into a chezmoi dotfiles repo), and writes through the symlink
# land on the target path. The fix (lib.nix `policyScript` block) also
# rebinds the resolved symlink target and its existing parent read-only.
#
# This check builds a sample dynamic wrapper via `agentSandboxLib.mkWrapPackage`
# with `policyContext = true` and asserts the generated script contains the
# expected symlink-handling anchors. It is a build-time Nix check, not a
# NixOS VM test; no bwrap is run.
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

  # `fsArmPkg` forces `dynamicFs = true`, which routes through `policyScript`.
  # `pkgs.hello` is a stand-in for `agent-sandbox-fs-arm`; the script text
  # references the path but the build does not execute it.
  sampleWrapper = agentSandboxLib.mkWrapPackage pkgs {
    package = pkgs.hello;
    binary = "hello";
    fsArmPkg = pkgs.hello;
    policyContext = true;
    policySocket = "/tmp/policy-symlink-regression.sock";
    sandboxPolicySocket = "/tmp/policy-symlink-regression-sandbox.sock";
  };
in
pkgs.runCommand "policy-symlink-regression" { } ''
  fail() { echo "FAIL: $*" >&2; exit 1; }

  # `mkWrapPackage` returns a symlinkJoin; the real script is the symlink
  # target of the wrapped binary.
  SCRIPT=$(readlink -f ${sampleWrapper}/bin/hello)
  [[ -n "$SCRIPT" && -f "$SCRIPT" ]] || fail "wrapped script not found at ${sampleWrapper}/bin/hello"
  cp "$SCRIPT" wrapper.sh

  # 1. Baseline: the logical config directory is ro-bound. The current
  #    implementation binds it via the `_asbx_ro_bind_once` dedup helper
  #    rather than a direct `RUNTIME_ARGS+=(--ro-bind ...)` call. This
  #    alone is insufficient for symlinked policy files (writes through
  #    the symlink land on the target path), so subsequent assertions
  #    cover the new symlink-target protection.
  grep -F -q '_asbx_user_config="$_agent_sandbox_home/.config/agent-sandbox"' wrapper.sh \
    || fail "logical config dir variable is not assigned"
  grep -F -q '_asbx_ro_bind_once "$_asbx_user_config"' wrapper.sh \
    || fail "logical config dir is not ro-bound (insufficient baseline missing)"

  # 2. The new dedup helper is defined.
  grep -F -q '_asbx_ro_bind_once()' wrapper.sh \
    || fail "_asbx_ro_bind_once() helper not defined"

  # 3. The new parent-walk helper is defined.
  grep -F -q '_asbx_existing_parent()' wrapper.sh \
    || fail "_asbx_existing_parent() helper not defined"

  # 4. The new symlink-target-parent resolver is defined.
  grep -F -q '_asbx_policy_target_parent()' wrapper.sh \
    || fail "_asbx_policy_target_parent() resolver not defined"

  # 5. The ro-bind helper appends to RUNTIME_ARGS (the actual mount mechanism).
  grep -F -q 'RUNTIME_ARGS+=(--ro-bind "$_asbx_path" "$_asbx_path")' wrapper.sh \
    || fail "_asbx_ro_bind_once body does not emit RUNTIME_ARGS ro-bind"

  # 6. Policy candidates are resolved via `readlink -f` to chase symlinks.
  grep -F -q 'readlink -f "$_asbx_policy_candidate"' wrapper.sh \
    || fail "readlink -f resolution of policy candidate missing"

  # 7. The resolved real path (the symlink target file itself) is ro-bound.
  grep -F -q '_asbx_ro_bind_once "$_asbx_policy_real"' wrapper.sh \
    || fail "ro-bind of resolved real path (symlink target) missing"

  # 8. The resolved target's existing parent (the symlink target's parent) is
  #    ro-bound. This guards the case where the target's parent is also outside
  #    the protected config tree (e.g. inside a chezmoi dotfiles repo).
  grep -F -q '_asbx_ro_bind_once "$_asbx_policy_parent"' wrapper.sh \
    || fail "ro-bind of resolved target's existing parent missing"

  # 9. The project .agent-sandbox directory is ro-bound when it exists.
  grep -F -q '_asbx_ro_bind_once "$_asbx_project_agent_sandbox"' wrapper.sh \
    || fail "project .agent-sandbox ro-bind missing"

  echo "PASS: policy-symlink protection regression guard satisfied"
  touch $out
''
