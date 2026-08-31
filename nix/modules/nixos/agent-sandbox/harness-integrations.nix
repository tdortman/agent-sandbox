{
  config,
  lib,
  pkgs,
  inputs,
  ...
}:

let
  cfg = config.agent-sandbox;
  codexPkg = flake.package "codex-desktop";
  contract = import ../../../lib/harness-integrations.nix;
  dshPkg = flake.package "dsh";
  flake = import ../../../lib/consumer.nix { inherit inputs pkgs; };
  harnessPkg = flake.package "harness-integrations";
  sandboxPkg = flake.package "agent-sandbox";
  requiredSystems = [
    "x86_64-linux"
    "aarch64-linux"
  ];
in
{
  options.agent-sandbox.dynamicProjectAttribution.enable = lib.mkEnableOption ''
    the DSH and Codex context adapter integrations
    (enables the complete compatible policy closure)
  '';

  config = lib.mkIf cfg.dynamicProjectAttribution.enable {
    agent-sandbox = {
      # One switch enables the gates needed by policy attribution. Explicit
      # conflicting values still fail the existing gate assertions.
      enable = lib.mkDefault true;

      gates = {
        filesystem.enable = lib.mkDefault true;
        resources.enable = lib.mkDefault true;
        syscalls.enable = lib.mkDefault true;
      };

      network = {
        enable = lib.mkDefault true;
        httpProxy.enable = lib.mkDefault true;
      };

      packages = lib.mkAfter [
        {
          package = codexPkg;
          binary = "codex-desktop";
          extraPkgs = [ harnessPkg ];
          name = "codex-desktop";
        }
        {
          package = dshPkg;
          binary = "dsh";
          extraPkgs = [ harnessPkg ];
          name = "dsh";
        }
      ];

      policy.dbus.enable = lib.mkDefault true;
      sudoPolicy = lib.mkDefault "approve";
    };

    assertions = [
      {
        assertion = lib.elem pkgs.stdenv.hostPlatform.system requiredSystems;
        message = "agent-sandbox.dynamicProjectAttribution requires a supported Linux system";
      }
      {
        assertion = contract.protocolMajor == 1;
        message = "agent-sandbox dynamic attribution requires context adapter protocol major 1";
      }
      {
        assertion =
          contract.codex.appServer.transport == "stdio-jsonl" && !contract.codex.appServer.sharedSocket;

        message = "Codex app-server attribution requires stdio JSON-RPC without a shared socket";
      }
      {
        assertion = contract.dsh.gitCommit == "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e";
        message = "DSH integration must use the pinned 0.1.1-rc.2 source commit";
      }
    ];

    environment = {
      sessionVariables = {
        AGENT_SANDBOX_CHILD = "${harnessPkg}/bin/agent-sandbox-child";
        AGENT_SANDBOX_CONTEXT_ADAPTER = "${harnessPkg}/bin/agent-sandbox-context-adapter";
        AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL = toString contract.protocolMajor;
        AGENT_SANDBOX_PROXY = "${sandboxPkg}/bin/agent-sandbox-proxy";
        AGENT_SANDBOX_DBUS_PROXY = "${sandboxPkg}/bin/agent-sandbox-dbus-proxy";
        AGENT_SANDBOX_CONTEXT_ADAPTER_REQUIRED = "1";
        AGENT_SANDBOX_CONTEXT_ADAPTER_SOCKET = cfg.policy.socketPath;
        CODEX_APP_SERVER_SHARED_SOCKET = "0";
        CODEX_APP_SERVER_TRANSPORT = contract.codex.appServer.transport;
        CODEX_CLI_PATH = "${codexPkg}/bin/codex";
      };

      systemPackages = lib.mkAfter [ harnessPkg ];
    };
  };
}
