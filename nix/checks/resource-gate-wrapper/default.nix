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
  lib,
  pkgs,
  inputs,
  ...
}:
let
  agentSandboxLib = import ../../modules/nixos/agent-sandbox/lib.nix {
    inherit lib;
    inherit (inputs) jail-nix;
  };
  nonResourceGateWrapper = agentSandboxLib.mkWrapPackage pkgs {
    package = pkgs.hello;
    binary = "hello";
    devicePaths = [ "/dev/agent-sandbox-regression-device" ];
    fsArmPkg = pkgs.hello;
    policyContext = true;
    policySocket = "/tmp/resource-gate-regression.sock";
    sandboxPolicySocket = "/tmp/resource-gate-regression-sandbox.sock";
  };
  resourceGateWrapper = agentSandboxLib.mkWrapPackage pkgs {
    package = pkgs.hello;
    binary = "hello";

    dbus = {
      enable = true;
      socketDirectory = "/run/user";
      upstreamAddress = null;
    };

    dbusProxyPkg = pkgs.hello;
    devicePaths = [ "/dev/agent-sandbox-regression-device" ];
    fsArmPkg = pkgs.hello;
    policyContext = true;
    policySocket = "/tmp/resource-gate-regression.sock";
    resourceGate = true;
    sandboxPolicySocket = "/tmp/resource-gate-regression-sandbox.sock";
    syscallArmPkg = pkgs.hello;
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

  # /run/wrappers is always hidden, including resource-gate mode.
  grep -F -q -- 'RUNTIME_ARGS+=(--tmpfs /run/wrappers)' rg-wrapper.sh \
    || fail "resource-gate: /run/wrappers must be hidden"

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

  # 5. /proc and /tmp are sandbox-private (overlay host root bind).
  grep -F -q -- '--proc /proc' rg-wrapper.sh \
    || fail "resource-gate: missing --proc /proc"
  grep -F -q -- '--tmpfs /tmp' rg-wrapper.sh \
    || fail "resource-gate: missing --tmpfs /tmp"

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

  # Both buses use relays, never a bind of the raw host system socket.
  grep -F -q -- 'for _asbx_dbus_bus in session system; do' rg-wrapper.sh \
    || fail "D-Bus: both bus relays must start"
  grep -F -q -- '--setenv DBUS_SYSTEM_BUS_ADDRESS "unix:path=$_asbx_dbus_dir/system.sock"' rg-wrapper.sh \
    || fail "D-Bus: missing system relay address"
  if grep -F -q -- '--ro-bind /run/dbus/system_bus_socket' rg-wrapper.sh; then
    fail "D-Bus: raw system bus must not be exposed"
  fi

  # --- Non-resource-gate mode assertions ---

  # 9. Broad --tmpfs /run IS present in non-resource-gate mode.
  grep -F -q -- 'RUNTIME_ARGS+=(--tmpfs /run)' nrg-wrapper.sh \
    || fail "non-resource-gate: missing broad --tmpfs /run"

  grep -F -q -- 'RUNTIME_ARGS+=(--tmpfs /run/wrappers)' nrg-wrapper.sh \
    || fail "non-resource-gate: /run/wrappers must be hidden"

  # 10. GPU auto-bind loop IS present in non-resource-gate mode.
  grep -F -q 'for _gpu in /dev/nvidia' nrg-wrapper.sh \
    || fail "non-resource-gate: GPU auto-bind loop should be present"

  # 11. Configured devicePaths ARE present in non-resource-gate mode.
  grep -F -q 'agent-sandbox-regression-device' nrg-wrapper.sh \
    || fail "non-resource-gate: configured devicePaths should be present"

  # 12. /tmp is sandbox-private in both dynamic wrappers.
  grep -F -q -- '--tmpfs /tmp' nrg-wrapper.sh \
    || fail "non-resource-gate: missing --tmpfs /tmp"

  # Execute the generated relay setup with socket-producing stand-ins.
  ${pkgs.python3}/bin/python3 - <<'PY'
  import json, os, pathlib, subprocess, tempfile

  wrapper = pathlib.Path("rg-wrapper.sh").read_text()
  start = wrapper.index('_asbx_dbus_root=')
  end = wrapper.index('RUNTIME_ARGS+=(--setenv DBUS_SYSTEM_BUS_ADDRESS', start)
  setup = wrapper[start:wrapper.index('\n', end)]
  with tempfile.TemporaryDirectory() as directory:
      root = pathlib.Path(directory)
      mock = root / "relay"
      mock.write_text("#!${pkgs.python3}/bin/python3\n" + """
  import json, os, pathlib, signal, socket, sys
  args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
  bus = args['--bus']
  pathlib.Path(os.environ['LOG_DIR'], bus).write_text(json.dumps(dict(args, pid=os.getpid())))
  if os.environ.get('FAIL_BUS') == bus:
      sys.exit(1)
  listener = socket.socket(socket.AF_UNIX)
  listener.bind(args['--listen'])
  listener.listen()
  signal.pause()
  """)
      mock.chmod(0o755)
      setup = setup.replace('/run/user', str(root / 'sockets'))
      setup = setup.replace('${pkgs.hello}/bin/agent-sandbox-dbus-proxy', str(mock))
      for override, failure in [(None, ""), ("unix:path=/custom-system-bus", ""), (None, "system")]:
          env = dict(os.environ, LOG_DIR=str(root), DBUS_SESSION_BUS_ADDRESS="unix:path=/session-bus", FAIL_BUS=failure)
          env.pop('DBUS_SYSTEM_BUS_ADDRESS', None)
          if override:
              env['DBUS_SYSTEM_BUS_ADDRESS'] = override
          script = 'set -eu\nRUNTIME_ARGS=()\n_agent_sandbox_cwd=/\n_agent_sandbox_home=/\n_agent_sandbox_project_root=/\n_agent_sandbox_session_id=test\n'
          script += setup + '\nprintf "%s\\n" "''${RUNTIME_ARGS[@]}"\n'
          result = subprocess.run(['bash', '-c', script], env=env, text=True, capture_output=True, timeout=10)
          assert result.returncode == (1 if failure else 0), result.stderr
          for bus in ['session', 'system']:
              args = json.loads((root / bus).read_text())
              expected = "unix:path=/session-bus" if bus == 'session' else override or "unix:path=/run/dbus/system_bus_socket"
              assert args['--upstream-address'] == expected, args
              assert args['--sandbox-session-id'] == 'test', args
              assert not pathlib.Path(args['--listen']).parent.exists(), args
              assert not pathlib.Path('/proc', str(args['pid'])).exists(), args
              if not failure:
                  assert 'DBUS_' + bus.upper() + '_BUS_ADDRESS\nunix:path=' + args['--listen'] in result.stdout, result.stdout
  print("PASS: both bus addresses, upstream override, and cleanup on success/failure")
  PY

  echo "PASS: resource-gate wrapper regression guard satisfied"
  touch $out
''
