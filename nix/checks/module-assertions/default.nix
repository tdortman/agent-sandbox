{
  pkgs,
  inputs,
  ...
}:
let
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
  contract =
    assert expectFailure socketPathMessage {
      agent-sandbox = {
        gates.filesystem.enable = true;

        policy = {
          sandboxSocketPath = "/run/agent-sandbox/shared.sock";
          socketPath = "/run/agent-sandbox/shared.sock";
        };
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
            allMethods = true;
            url = "https://api.example.com/v1";
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
  dbusGateMessage = "agent-sandbox.policy.dbus.enable requires gates.resources.enable";
  expectFailure =
    expected: extraModule: failedModuleMessages (mkNixosSystem extraModule) == [ expected ];
  failedMessages =
    system:
    map (entry: entry.message) (builtins.filter (entry: !entry.assertion) system.config.assertions);
  failedModuleMessages =
    system: builtins.filter (message: builtins.elem message assertionMessages) (failedMessages system);
  mkNixosSystem =
    extraModule:
    inputs.nixpkgs.lib.nixosSystem {
      modules = [
        ../../modules/nixos/agent-sandbox
        {
          agent-sandbox.enable = true;
          nixpkgs.pkgs = pkgs;
          system.stateVersion = "26.11";
        }
        extraModule
      ];

      specialArgs = { inherit inputs; };
      system = pkgs.stdenv.hostPlatform.system;
    };
  proxyCredentialsMessage = "agent-sandbox HTTP proxy CA certificate and key must be supplied together and use absolute paths";
  proxyGidMessage = "agent-sandbox.network.httpProxy.gid must be nonzero when explicitly configured";
  proxyNetworkMessage = "agent-sandbox.network.httpProxy.enable requires network.enable";
  proxyRulesMessage = "agent-sandbox.network.httpProxy.declarativeAllow/declarativeDeny require httpProxy.enable (configured URLs: https://api.example.com/v1)";
  resourceGateMessage = "agent-sandbox.gates.resources.enable requires gates.filesystem.enable";
  socketPathMessage = "agent-sandbox.policy.socketPath and sandboxSocketPath must differ when policy is enabled";
  upstreamCidrMessage = "agent-sandbox.network.httpProxy.upstreamAllowCidrs entries must be non-empty CIDR strings";
  validSystem = mkNixosSystem {
    agent-sandbox = {
      gates = {
        filesystem.enable = true;
        resources.enable = true;
      };

      network = {
        enable = true;

        httpProxy = {
          enable = true;
          caCertificateFile = "/run/credentials/proxy-ca.crt";
          caPrivateKeyFile = "/run/credentials/proxy-ca.key";
          gid = 1;
          upstreamAllowCidrs = [ "192.0.2.0/24" ];
        };
      };

      policy.dbus.enable = true;
    };
  };
in
assert contract;
pkgs.runCommand "module-assertions" { } ''
  touch $out
''
