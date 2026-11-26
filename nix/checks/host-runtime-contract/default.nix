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
  contract =
    assert runtime.policyContext;
    assert runtime.policySocket == "/run/test/policyd.sock";
    assert runtime.exportedJson == "/var/lib/test/policy.json";
    assert runtime.exportedNix == "/var/lib/test/policy.nix";
    assert runtime.interactiveApproval == false;
    assert runtime.approvalTimeout == 47.5;
    assert runtime.pauseClockWhileFrozen == false;
    assert pausingRuntime.pauseClockWhileFrozen == true;
    assert runtime.autoSpawnPolicyUi;
    assert runtime.uiBackend == "test-ui";
    assert runtime.network.netnsName == "test-netns";
    assert runtime.network.vethHost == "test-veth-host";
    assert runtime.network.vethNetns == "test-veth-netns";
    assert runtime.network.netnsIp == "192.0.2.2";
    assert runtime.network.netnsIp6 == "2001:db8::2";
    assert runtime.network.netnsIp6Prefix == 64;
    assert runtime.network.netnsEnter == "/run/test/netns-enter";
    assert runtime.queueNumber == 9;
    assert runtime.hostIp == "192.0.2.1";
    assert runtime.hostIp6 == "2001:db8::1";
    # approval wait + UI registration wait + margin
    assert runtime.policyTimeout == 100.0;
    assert runtime.dnsForwardTarget == "192.0.2.53:53";
    true;
  # Follow a wrapper's chain of launcher scripts and fail unless the netns
  # enter helper is run with exactly the expected flags in one of them.
  expectEnterLine = label: wrapper: expected: ''
    script=$(readlink -f ${wrapper}/bin/sandboxed-hello)
    found=
    for _ in 1 2 3 4; do
      if grep -F -q -- ${lib.escapeShellArg expected} "$script"; then
        found=1
        break
      fi
      next=$(grep -o '/nix/store/[^ "]*/bin/sandboxed-[^ "]*' "$script" | head -n 1 || true)
      [ -n "$next" ] || break
      script=$(readlink -f "$next")
    done
    [ -n "$found" ] || fail "${label}: no launcher runs: ${expected}"
  '';
  expectNoTimeNamespace = label: wrapper: ''
    script=$(readlink -f ${wrapper}/bin/sandboxed-hello)
    for _ in 1 2 3 4; do
      if grep -F -q -- '--new-time-namespace' "$script"; then
        fail "${label}: wrapper requests a time namespace"
      fi
      next=$(grep -o '/nix/store/[^ "]*/bin/sandboxed-[^ "]*' "$script" | head -n 1 || true)
      [ -n "$next" ] || break
      script=$(readlink -f "$next")
    done
  '';
  # Static (jail.nix) and dynamic-FS wrappers both go through the netns
  # enter prefix.
  mkWrapper =
    {
      dynamic,
      pause,
    }:
    agentSandboxLib.mkWrapPackage pkgs {
      package = pkgs.hello;
      binary = "hello";
      fsArmPkg = if dynamic then pkgs.hello else null;

      network = {
        netnsEnter = "/run/test/netns-enter";
        netnsName = "agent-sandbox";
      };

      runtime = {
        hostIp = "169.254.100.1";
        httpProxy.enable = false;
        network = { };
        pauseClockWhileFrozen = pause;
        policyContext = false;
      };

      syscallArmPkg = pkgs.hello;
    };
  pausingRuntime = agentSandboxLib.mkRuntime {
    netnsEnter = "/run/test/netns-enter";

    rootCfg = rootCfg // {
      policy = rootCfg.policy // {
        pauseClockWhileFrozen = true;
      };
    };
  };
  rootCfg = {
    gates.filesystem.enable = false;

    network = {
      enable = true;
      dnsForwardTarget = "192.0.2.53:53";
      hostIp = "192.0.2.1";
      hostIp6 = "2001:db8::1";
      netnsIp = "192.0.2.2";
      netnsIp6 = "2001:db8::2";
      netnsIp6Prefix = 64;
      netnsName = "test-netns";
      policyTimeout = 19.0;
      queueNumber = 9;
      vethHost = "test-veth-host";
      vethNetns = "test-veth-netns";
    };

    policy = {
      approvalTimeout = 47.5;
      autoSpawnPolicyUi = true;
      exportedJson = "/var/lib/test/policy.json";
      exportedNix = "/var/lib/test/policy.nix";
      interactiveApproval = false;
      pauseClockWhileFrozen = false;
      socketPath = "/run/test/policyd.sock";
      uiBackend = "test-ui";
    };

    sudoPolicy = "deny";
  };
  runtime = agentSandboxLib.mkRuntime {
    inherit rootCfg;
    netnsEnter = "/run/test/netns-enter";
  };
in
assert contract;
pkgs.runCommand "host-runtime-contract" { } ''
  fail() { echo "FAIL: $*" >&2; exit 1; }

  ${lib.concatMapStrings
    (dynamic: ''
      ${expectEnterLine "pause on (dynamic=${lib.boolToString dynamic})" (mkWrapper {
        inherit dynamic;
        pause = true;
      }) "/run/test/netns-enter --new-time-namespace agent-sandbox"}
      ${expectEnterLine "pause off (dynamic=${lib.boolToString dynamic})" (mkWrapper {
        inherit dynamic;
        pause = false;
      }) "/run/test/netns-enter agent-sandbox"}
      ${expectNoTimeNamespace "pause off (dynamic=${lib.boolToString dynamic})" (mkWrapper {
        inherit dynamic;
        pause = false;
      })}
    '')
    [
      true
      false
    ]
  }
  touch $out
''
