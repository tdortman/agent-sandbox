{ pkgs, inputs, ... }:

let
  contract = import ../../lib/harness-integrations.nix;
  disabled = mkSystem { };
  enabled = mkSystem { agent-sandbox.dynamicProjectAttribution.enable = true; };
  enabledPackages = map (package: package.name) enabled.config.agent-sandbox.packages;
  lib = inputs.nixpkgs.lib;
  mkSystem =
    extraModule:
    lib.nixosSystem {
      inherit system;

      modules = [
        module
        {
          nixpkgs.pkgs = pkgs;
          system.stateVersion = "26.11";
        }
        extraModule
      ];

      specialArgs = { inherit inputs; };
    };
  module = ../../modules/nixos/agent-sandbox;
  system = pkgs.stdenv.hostPlatform.system;
  variables = enabled.config.environment.sessionVariables;
in
assert contract.protocolMajor == 1;
assert contract.dsh.version == "0.1.1-rc.2";
assert contract.dsh.gitCommit == "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e";
assert contract.codex.desktop.version == "26.825.51511";
assert contract.codex.runtime.version == "0.151.0-alpha.7.2";
assert contract.codex.appServer.transport == "stdio-jsonl";
assert contract.codex.appServer.sharedSocket == false;
assert !contract.codex.desktop.electronAsarPatch;
assert !disabled.config.agent-sandbox.dynamicProjectAttribution.enable;
assert !(disabled.config.environment.sessionVariables ? AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL);
assert enabled.config.agent-sandbox.enable;
assert enabled.config.agent-sandbox.gates.filesystem.enable;
assert enabled.config.agent-sandbox.gates.resources.enable;
assert enabled.config.agent-sandbox.gates.syscalls.enable;
assert enabled.config.agent-sandbox.network.enable;
assert enabled.config.agent-sandbox.network.httpProxy.enable;
assert enabled.config.agent-sandbox.policy.dbus.enable;
assert enabled.config.agent-sandbox.sudoPolicy == "approve";
assert lib.elem "dsh" enabledPackages;
assert lib.elem "codex-desktop" enabledPackages;
assert variables.AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL == "1";
assert variables.AGENT_SANDBOX_CONTEXT_ADAPTER_REQUIRED == "1";
assert variables.CODEX_APP_SERVER_TRANSPORT == "stdio-jsonl";
assert variables.CODEX_APP_SERVER_SHARED_SOCKET == "0";
pkgs.runCommand "harness-integrations" { } ''
  touch $out
''
