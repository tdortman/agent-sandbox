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

  rootCfg = {
    policy = {
      socketPath = "/run/test/policyd.sock";
      sandboxSocketPath = "/run/test/sandbox-policyd.sock";
      exportedJson = "/var/lib/test/policy.json";
      exportedNix = "/var/lib/test/policy.nix";
      interactiveApproval = false;
      approvalTimeout = 47.5;
      autoSpawnPolicyUi = true;
      uiBackend = "test-ui";
    };
    network = {
      enable = true;
      netnsName = "test-netns";
      vethHost = "test-veth-host";
      vethNetns = "test-veth-netns";
      netnsIp = "192.0.2.2";
      netnsIp6 = "2001:db8::2";
      netnsIp6Prefix = 64;
      queueNumber = 9;
      hostIp = "192.0.2.1";
      hostIp6 = "2001:db8::1";
      policyTimeout = 19.0;
      dnsForwardTarget = "192.0.2.53:53";
    };
    gates.filesystem.enable = false;
    sudoPolicy = "deny";
  };

  runtime = agentSandboxLib.mkRuntime {
    inherit rootCfg;
    netnsEnter = "/run/test/netns-enter";
  };

  contract =
    assert runtime.policyContext;
    assert runtime.policySocket == "/run/test/policyd.sock";
    assert runtime.sandboxPolicySocket == "/run/test/sandbox-policyd.sock";
    assert runtime.exportedJson == "/var/lib/test/policy.json";
    assert runtime.exportedNix == "/var/lib/test/policy.nix";
    assert runtime.interactiveApproval == false;
    assert runtime.approvalTimeout == 47.5;
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
    assert runtime.policyTimeout == 47.5;
    assert runtime.dnsForwardTarget == "192.0.2.53:53";
    true;
in
assert contract;
pkgs.runCommand "host-runtime-contract" { } ''
  touch $out
''
