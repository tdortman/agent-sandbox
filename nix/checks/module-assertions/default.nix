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
    proxyAltPortsMessage
    invalidPackageNameMessage
    invalidPackageNameDotDotMessage
    duplicatePackageNameMessage
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

    assert expectFailure proxyAltPortsMessage {
      agent-sandbox.network = {
        enable = true;
        httpProxy.http3.altUdpPorts = [ 4444 ];
      };
    };

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.network = {
              enable = true;

              httpProxy = {
                enable = true;
                http10UpstreamOrigins = [ "http://example.com/path" ];
              };
            };
          };
        in
        builtins.deepSeq system.config.agent-sandbox.network.httpProxy.http10UpstreamOrigins true
      )).success;

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.network = {
              enable = true;

              httpProxy = {
                enable = true;
                http10UpstreamOrigins = [ "http://*.example.com" ];
              };
            };
          };
        in
        builtins.deepSeq system.config.agent-sandbox.network.httpProxy.http10UpstreamOrigins true
      )).success;

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

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.policy.filesystem.declarativeAllow = [
              {
                path = "relative/path";
              }
            ];
          };
        in
        builtins.deepSeq system.config.agent-sandbox.policy.filesystem.declarativeAllow true
      )).success;

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.policy.filesystem.declarativeDeny = [
              {
                access = "banana";
                path = "/etc/agent-sandbox";
              }
            ];
          };
        in
        builtins.deepSeq system.config.agent-sandbox.policy.filesystem.declarativeDeny true
      )).success;

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.policy.resources.declarativeAllow = [
              {
                access = "open_read";
                kind = "chardev";
                path = "/dev/kvm";
              }
            ];
          };
        in
        builtins.deepSeq system.config.agent-sandbox.policy.resources.declarativeAllow true
      )).success;

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.policy.resources.declarativeDeny = [
              {
                access = "banana";
                kind = "device";
                path = "/dev/kvm";
              }
            ];
          };
        in
        builtins.deepSeq system.config.agent-sandbox.policy.resources.declarativeDeny true
      )).success;

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.policy.sudo.declarativeAllow = [
              {
                argv = [ ];
              }
            ];
          };
        in
        builtins.deepSeq system.config.agent-sandbox.policy.sudo.declarativeAllow true
      )).success;

    assert expectFailure invalidPackageNameMessage {
      agent-sandbox.packages = [
        {
          package = pkgs.hello;
          name = "foo/bar";
        }
      ];
    };

    assert expectFailure invalidPackageNameDotDotMessage {
      agent-sandbox.packages = [
        {
          package = pkgs.hello;
          name = "..";
        }
      ];
    };

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.packages = [
              {
                package = pkgs.hello;

                policy.filesystem.allow = [
                  {
                    path = "relative/path";
                  }
                ];
              }
            ];
          };
        in
        builtins.deepSeq (map (p: p.policy) system.config.agent-sandbox.packages) true
      )).success;

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.packages = [
              {
                package = pkgs.hello;

                policy.filesystem.allow = [
                  {
                    access = "banana";
                    path = "/etc/agent-sandbox";
                  }
                ];
              }
            ];
          };
        in
        builtins.deepSeq (map (p: p.policy) system.config.agent-sandbox.packages) true
      )).success;

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.packages = [
              {
                package = pkgs.hello;

                policy.sudo.allow = [
                  {
                    argv = [ ];
                  }
                ];
              }
            ];
          };
        in
        builtins.deepSeq (map (p: p.policy) system.config.agent-sandbox.packages) true
      )).success;

    assert expectFailure duplicatePackageNameMessage {
      agent-sandbox.packages = [
        {
          package = pkgs.hello;
          name = "dup";

          policy.sudo.allow = [
            {
              argv = [
                "systemctl"
                "restart"
              ];
            }
          ];
        }
        {
          package = pkgs.hello;
          name = "dup";

          policy.sudo.deny = [
            {
              argv = [ "rm" ];
            }
          ];
        }
      ];
    };

    assert
      let
        json = builtins.fromJSON validSystem.config.environment.etc."agent-sandbox/packages/omp.json".text;
      in
      json.network == {
        direct = {
          allow = [ ];
          deny = [ ];
        };

        http = {
          allow = [ ];
          deny = [ ];
        };
      }
      &&
        json.sudo == {
          allow = [
            {
              argv = [
                "systemctl"
                "restart"
              ];
            }
          ];

          deny = [ ];
        }
      &&
        json.filesystem == {
          allow = [
            {
              access = "read";
              path = "~/.agents";
            }
          ];

          deny = [ ];
        }
      && !(json ? resources)
      && !(json ? dbus);

    assert
      let
        system = mkNixosSystem {
          agent-sandbox.packages = [
            {
              package = pkgs.hello;
            }
          ];
        };
      in
      !(system.config.environment.etc ? "agent-sandbox/packages/hello.json");

    assert
      let
        system = mkNixosSystem {
          agent-sandbox.packages = [
            {
              package = pkgs.hello;

              policy.network.direct.allow = [
                {
                  host = "example.com";
                  port = 443;
                }
              ];
            }
          ];
        };
      in
      system.config.environment.etc ? "agent-sandbox/packages/hello.json";

    assert lib.hasInfix "omp=/etc/agent-sandbox/packages/omp.json"
      validSystem.config.systemd.services.agent-sandbox-policy.serviceConfig.ExecStart;

    assert validSystem.config.agent-sandbox.network.httpProxy.http3.enable == false;
    assert failedModuleMessages validSystem == [ ];

    assert
      let
        json = builtins.fromJSON validSystem.config.environment.etc."agent-sandbox/policy.json".text;
      in
      json.network == {
        direct = {
          allow = [ ];
          deny = [ ];
        };

        http = {
          allow = [ ];
          deny = [ ];
        };
      }
      &&
        json.sudo == {
          allow = [
            {
              argv = [
                "systemctl"
                "restart"
              ];
            }
          ];

          deny = [
            {
              argv = [
                "rm"
                "-rf"
              ];
            }
          ];
        }
      &&
        json.filesystem == {
          allow = [
            {
              access = "all";
              path = "/nix/store";
            }
            {
              access = "read";
              path = "~/.config/agent-sandbox";
            }
            {
              access = "read_write";
              path = "/etc/agent-sandbox";
            }
          ];

          deny = [
            {
              access = "all";
              path = "~/.config/agent-sandbox";
            }
            {
              access = "all";
              path = "./.agent-sandbox";
            }
            {
              access = "all";
              path = "~/.ssh";
            }
          ];
        }
      &&
        json.resources == {
          allow = [
            {
              access = "connect";
              kind = "unix_socket";
              path = "~/.local/state/omp/run";
            }
            {
              access = "open_read_write";
              kind = "device";
              path = "/dev/kvm";
            }
          ];

          deny = [
            {
              access = "send";
              kind = "unix_socket";
              path = "~/.cache/agent-sandbox";
            }
          ];
        };
    true;
  dbusGateMessage = "agent-sandbox.policy.dbus.enable requires gates.resources.enable";
  duplicatePackageNameMessage = "agent-sandbox packages declaring policy must have unique effective names (each emits /etc/agent-sandbox/packages/<name>.json); duplicates: dup";
  expectFailure =
    expected: extraModule: failedModuleMessages (mkNixosSystem extraModule) == [ expected ];
  failedMessages =
    system:
    map (entry: entry.message) (builtins.filter (entry: !entry.assertion) system.config.assertions);
  failedModuleMessages =
    system: builtins.filter (message: builtins.elem message assertionMessages) (failedMessages system);
  invalidPackageNameDotDotMessage = "agent-sandbox package names must be non-empty and contain neither '/' nor '..', got: ..";
  invalidPackageNameMessage = "agent-sandbox package names must be non-empty and contain neither '/' nor '..', got: foo/bar";
  lib = inputs.nixpkgs.lib;
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
  proxyAltPortsMessage = "agent-sandbox.network.httpProxy.http3.altUdpPorts requires http3.enable";
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

      packages = [
        {
          package = pkgs.hello;
          name = "omp";

          policy = {
            filesystem.allow = [
              {
                access = "read";
                path = "~/.agents";
              }
            ];

            sudo.allow = [
              {
                argv = [
                  "systemctl"
                  "restart"
                ];
              }
            ];
          };
        }
      ];

      policy = {
        dbus.enable = true;

        filesystem = {
          declarativeAllow = [
            {
              access = "read";
              path = "~/.config/agent-sandbox";
            }
            {
              access = "read_write";
              path = "/etc/agent-sandbox";
            }
          ];

          declarativeDeny = [
            {
              access = "all";
              path = "~/.ssh";
            }
          ];
        };

        resources = {
          declarativeAllow = [
            {
              access = "connect";
              kind = "unix_socket";
              path = "~/.local/state/omp/run";
            }
            {
              access = "open_read_write";
              kind = "device";
              path = "/dev/kvm";
            }
          ];

          declarativeDeny = [
            {
              access = "send";
              kind = "unix_socket";
              path = "~/.cache/agent-sandbox";
            }
          ];
        };

        sudo = {
          declarativeAllow = [
            {
              argv = [
                "systemctl"
                "restart"
              ];
            }
          ];

          declarativeDeny = [
            {
              argv = [
                "rm"
                "-rf"
              ];
            }
          ];
        };
      };
    };
  };
in
assert contract;
pkgs.runCommand "module-assertions" { } ''
  touch $out
''
