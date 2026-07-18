{
  pkgs,
  inputs,
  ...
}:
let
  mkNixosSystem =
    extraModule:
    inputs.nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      specialArgs = { inherit inputs; };
      modules = [
        ../../modules/nixos/agent-sandbox
        {
          nixpkgs.pkgs = pkgs;
          agent-sandbox.enable = true;
          system.stateVersion = "26.11";
        }
        extraModule
      ];
    };

  failedMessages =
    system:
    map (entry: entry.message) (builtins.filter (entry: !entry.assertion) system.config.assertions);

  expectFailure =
    expected: extraModule: failedModuleMessages (mkNixosSystem extraModule) == [ expected ];

  socketPathMessage = "agent-sandbox.policy.socketPath and sandboxSocketPath must differ when policy is enabled";
  resourceGateMessage = "agent-sandbox.gates.resources.enable requires gates.filesystem.enable";
  dbusGateMessage = "agent-sandbox.policy.dbus.enable requires gates.resources.enable";
  proxyNetworkMessage = "agent-sandbox.network.httpProxy.enable requires network.enable";
  proxyRulesMessage = "agent-sandbox.network.httpProxy.declarativeAllow/declarativeDeny require httpProxy.enable (configured URLs: https://api.example.com/v1)";
  proxyCredentialsMessage = "agent-sandbox HTTP proxy CA certificate and key must be supplied together and use absolute paths";
  upstreamCidrMessage = "agent-sandbox.network.httpProxy.upstreamAllowCidrs entries must be non-empty CIDR strings";
  proxyGidMessage = "agent-sandbox.network.httpProxy.gid must be nonzero when explicitly configured";
  assertionMessages = [
    socketPathMessage
    resourceGateMessage
    dbusGateMessage
    proxyNetworkMessage
    proxyRulesMessage
    proxyCredentialsMessage
    upstreamCidrMessage
    proxyGidMessage
  ];
  failedModuleMessages =
    system: builtins.filter (message: builtins.elem message assertionMessages) (failedMessages system);

  validSystem = mkNixosSystem {
    agent-sandbox = {
      gates.filesystem.enable = true;
      gates.resources.enable = true;
      policy.dbus.enable = true;
      network = {
        enable = true;
        httpProxy = {
          enable = true;
          caCertificateFile = "/run/credentials/proxy-ca.crt";
          caPrivateKeyFile = "/run/credentials/proxy-ca.key";
          upstreamAllowCidrs = [ "192.0.2.0/24" ];
          gid = 1;
        };
      };
    };
  };

  contract =
    assert expectFailure socketPathMessage {
      agent-sandbox.gates.filesystem.enable = true;
      agent-sandbox.policy = {
        socketPath = "/run/agent-sandbox/shared.sock";
        sandboxSocketPath = "/run/agent-sandbox/shared.sock";
      };
    };
    assert expectFailure resourceGateMessage {
      agent-sandbox.gates.resources.enable = true;
    };
    assert expectFailure dbusGateMessage {
      agent-sandbox.policy.dbus.enable = true;
    };
    assert expectFailure proxyNetworkMessage {
      agent-sandbox.network.httpProxy.enable = true;
    };
    assert expectFailure proxyRulesMessage {
      agent-sandbox.network = {
        enable = true;
        httpProxy.declarativeAllow = [
          {
            url = "https://api.example.com/v1";
            allMethods = true;
          }
        ];
      };
    };
    assert expectFailure proxyCredentialsMessage {
      agent-sandbox.network.httpProxy.caCertificateFile = "/run/credentials/proxy-ca.crt";
    };
    assert expectFailure proxyCredentialsMessage {
      agent-sandbox.network.httpProxy = {
        caCertificateFile = "relative/proxy-ca.crt";
        caPrivateKeyFile = "relative/proxy-ca.key";
      };
    };
    assert expectFailure upstreamCidrMessage {
      agent-sandbox.network.httpProxy.upstreamAllowCidrs = [ "192.0.2.0" ];
    };
    assert expectFailure proxyGidMessage {
      agent-sandbox.network.httpProxy.gid = 0;
    };
    assert failedModuleMessages validSystem == [ ];
    true;
in
assert contract;
pkgs.runCommand "module-assertions" { } ''
  touch $out
''
