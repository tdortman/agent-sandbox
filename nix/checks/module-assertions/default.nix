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
    proxyClientIdentitiesMessage
    upstreamCidrMessage
    proxyGidMessage
    proxyAltPortsMessage
    invalidPackageNameMessage
    invalidPackageNameDotDotMessage
    duplicatePackageNameMessage
    secretsRequireDbusMessage
    secretsHostSelectorMessage
    secretsReservedAttrMessage
    clockPauseNetworkMessage
    clockPauseKernelVersionMessage
  ];
  contract =
    assert
      let
        packages =
          (mkNixosSystem {
            agent-sandbox.packages = [
              {
                package = pkgs.hello;

                launchArgs = {
                  sandboxed = [ "--greeting=hello world" ];
                  unsandboxed = [ "--greeting=host" ];
                };

                launchHook = {
                  sandboxed = "unset XDG_DATA_HOME";
                  unsandboxed = "export HOST_ONLY=1";
                };
              }
              { package = pkgs.hello; }
            ];
          }).config.agent-sandbox.packages;
      in
      (builtins.head packages).launchHook.sandboxed == "unset XDG_DATA_HOME"
      && (builtins.elemAt packages 1).launchHook.sandboxed == ""
      && (builtins.head packages).launchArgs.sandboxed == [ "--greeting=hello world" ]
      && (builtins.elemAt packages 1).launchArgs.sandboxed == [ ]
      && (builtins.head packages).launchArgs.unsandboxed == [ "--greeting=host" ]
      && (builtins.head packages).launchHook.unsandboxed == "export HOST_ONLY=1"
      && (builtins.elemAt packages 1).launchArgs.unsandboxed == [ ]
      && (builtins.elemAt packages 1).launchHook.unsandboxed == "";
    assert
      !(builtins.tryEval (
        builtins.deepSeq
          (mkNixosSystem { agent-sandbox.network.httpProxy.h2cUpstreamOrigins = [ "https://example.test" ]; })
          .config.agent-sandbox.network.httpProxy.h2cUpstreamOrigins
          true
      )).success;
    assert expectFailure socketPathMessage {
      agent-sandbox = {
        gates.filesystem.enable = true;
        policy.socketPath = "/run/agent-sandbox/shared/policy.sock";
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
    assert
      let
        json = builtins.fromJSON system.config.environment.etc."agent-sandbox/policy.json".text;
        system = mkNixosSystem {
          agent-sandbox.network = {
            enable = true;

            httpProxy = {
              enable = true;

              declarativeAllow = [
                {
                  allMethods = true;
                  url = "https://api.example.com/v1";
                }
                {
                  allMethods = true;
                  url = "https://api.example.com:8080/v1";
                }
                {
                  allMethods = true;
                  port = 8443;
                  url = "https://api.example.com/v1";
                }
                {
                  allMethods = true;
                  port = 8443;
                  url = "https://api.example.com:8443/v1";
                }
              ];
            };
          };
        };
      in
      json.network.http.allow == [
        {
          methods = [ ];
          port = 443;
          url = "https://api.example.com/v1";
        }
        {
          methods = [ ];
          port = 8080;
          url = "https://api.example.com/v1";
        }
        {
          methods = [ ];
          port = 8443;
          url = "https://api.example.com/v1";
        }
        {
          methods = [ ];
          port = 8443;
          url = "https://api.example.com/v1";
        }
      ];

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.network = {
              enable = true;

              httpProxy = {
                enable = true;

                declarativeAllow = [
                  {
                    allMethods = true;
                    port = 9443;
                    url = "https://api.example.com:8443/v1";
                  }
                ];
              };
            };
          };
        in
        system.config.environment.etc."agent-sandbox/policy.json".text
      )).success;

    assert
      let
        json =
          builtins.fromJSON
            system.config.environment.etc."agent-sandbox/packages/http-ports.json".text;
        system = mkNixosSystem {
          agent-sandbox.packages = [
            {
              package = pkgs.hello;
              name = "http-ports";

              policy.network.http.allow = [
                {
                  allMethods = true;
                  port = 8443;
                  url = "https://api.example.com/v1";
                }
              ];
            }
          ];
        };
      in
      json.network.http.allow == [
        {
          methods = [ ];
          port = 8443;
          url = "https://api.example.com/v1";
        }
      ];

    assert expectFailure proxyCredentialsMessage {
      agent-sandbox.network.httpProxy.caCertificateFile = "/run/credentials/proxy-ca.crt";
    };

    assert expectFailure proxyCredentialsMessage {
      agent-sandbox.network.httpProxy = {
        caCertificateFile = "relative/proxy-ca.crt";
        caPrivateKeyFile = "relative/proxy-ca.key";
      };
    };

    assert expectFailure proxyClientIdentitiesMessage {
      agent-sandbox.network.httpProxy.upstreamClientIdentitiesFile = "relative/identities.json";
    };

    assert
      !(builtins.tryEval (
        let
          system = mkNixosSystem {
            agent-sandbox.network.httpProxy.http3.upstreamHandshakeTimeoutMs = 0;
          };
        in
        builtins.deepSeq system.config.agent-sandbox.network.httpProxy.http3.upstreamHandshakeTimeoutMs true
      )).success;

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
      && !(json ? dbus)
      &&
        json.secrets == {
          allow = [
            {
              access = "all";
              collection = "default";
              comment = "omp own partition";
              partition = "own_package";
            }
          ];

          deny = [
            {
              access = "delete";
              collection = "default";
              partition = "host";
            }
          ];
        };

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
    assert validSystem.config.agent-sandbox.network.httpProxy.http3.upstreamHandshakeTimeoutMs == 2000;
    assert
      builtins.stringLength validSystem.config.systemd.services.agent-sandbox-proxy.serviceConfig.ExecStart
      > 0;
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
        }
      &&
        json.secrets == {
          allow = [
            {
              access = "read";
              attributes.service = "gh:github.com";
              collection = "default";
              comment = "shared GitHub CLI token";
              partition = "host";
            }
          ];

          deny = [
            {
              access = "delete";
              collection = "*";
              partition = "host";
            }
          ];
        };

    # Secret Service module assertions and legacy D-Bus migration warnings.
    assert expectFailure secretsRequireDbusMessage {
      agent-sandbox.policy.secrets.declarativeAllow = [
        {
          access = "all";
          partition = "own_package";
        }
      ];
    };

    assert expectFailure secretsRequireDbusMessage {
      agent-sandbox.packages = [
        {
          package = pkgs.hello;
          name = "codex";

          policy.secrets.allow = [
            {
              access = "all";
              partition = "own_package";
            }
          ];
        }
      ];
    };

    assert expectFailure secretsHostSelectorMessage {
      agent-sandbox = {
        gates = {
          filesystem.enable = true;
          resources.enable = true;
        };

        policy = {
          dbus.enable = true;

          secrets.declarativeAllow = [
            {
              access = "read";
              partition = "host";
            }
          ];
        };
      };
    };

    assert expectFailure secretsHostSelectorMessage {
      agent-sandbox = {
        gates = {
          filesystem.enable = true;
          resources.enable = true;
        };

        packages = [
          {
            package = pkgs.hello;
            name = "codex";

            policy.secrets.allow = [
              {
                access = "read";
                partition = "host";
              }
            ];
          }
        ];

        policy.dbus.enable = true;
      };
    };

    assert expectFailure secretsReservedAttrMessage {
      agent-sandbox = {
        gates = {
          filesystem.enable = true;
          resources.enable = true;
        };

        policy = {
          dbus.enable = true;

          secrets.declarativeAllow = [
            {
              access = "read";
              attributes."agent-sandbox:package" = "codex";
              partition = "host";
            }
          ];
        };
      };
    };

    assert expectFailure secretsReservedAttrMessage {
      agent-sandbox = {
        gates = {
          filesystem.enable = true;
          resources.enable = true;
        };

        packages = [
          {
            package = pkgs.hello;
            name = "codex";

            policy.secrets.deny = [
              {
                access = "read";
                attributes."agent-sandbox:custom" = "x";
                partition = "host";
              }
            ];
          }
        ];

        policy.dbus.enable = true;
      };
    };

    assert expectFailure clockPauseNetworkMessage {
      agent-sandbox.policy.pauseClockWhileFrozen = true;
    };

    assert expectFailure clockPauseKernelVersionMessage {
      agent-sandbox = {
        network.enable = true;
        policy.pauseClockWhileFrozen = true;
      };

      # The newest kernel series below the module's supported floor.
      boot.kernelPackages = pkgs.linuxPackages_6_12;
    };

    assert
      let
        system = mkNixosSystem {
          agent-sandbox = {
            network.enable = true;
            policy.pauseClockWhileFrozen = true;
          };
        };
      in
      failedModuleMessages system == [ ]
      && builtins.elem "agent_sandbox_timens" system.config.boot.kernelModules
      && lib.hasInfix "--pause-clock-while-frozen" system.config.systemd.services.agent-sandbox-policy.serviceConfig.ExecStart;

    assert
      !(lib.hasInfix "--pause-clock-while-frozen" validSystem.config.systemd.services.agent-sandbox-policy.serviceConfig.ExecStart)
      && !(builtins.elem "agent_sandbox_timens" validSystem.config.boot.kernelModules);

    # Legacy literal org.freedesktop.secrets D-Bus rules emit warnings (global
    # and per-package), while wildcard org.freedesktop.* does not.
    assert
      let
        globalWarnSystem = mkNixosSystem {
          agent-sandbox = {
            gates = {
              filesystem.enable = true;
              resources.enable = true;
            };

            policy.dbus = {
              enable = true;

              declarativeAllow = [
                {
                  target = {
                    destination = "org.freedesktop.secrets";
                    interface = "org.freedesktop.Secret.Service";
                    member = "OpenSession";
                    objectPath = "/org/freedesktop/secrets";
                    signature = "sv";
                  };
                }
              ];
            };
          };
        };
        pkgWarnSystem = mkNixosSystem {
          agent-sandbox = {
            gates = {
              filesystem.enable = true;
              resources.enable = true;
            };

            packages = [
              {
                package = pkgs.hello;
                name = "codex";

                policy.dbus.deny = [
                  {
                    target = {
                      destination = "org.freedesktop.secrets";
                      interface = "*";
                      member = "*";
                      objectPath = "*";
                      signature = "*";
                    };
                  }
                ];
              }
            ];

            policy.dbus.enable = true;
          };
        };
        wildcardSystem = mkNixosSystem {
          agent-sandbox = {
            gates = {
              filesystem.enable = true;
              resources.enable = true;
            };

            policy.dbus = {
              enable = true;

              declarativeAllow = [
                {
                  target = {
                    destination = "org.freedesktop.*";
                    interface = "*";
                    member = "*";
                    objectPath = "*";
                    signature = "*";
                  };
                }
              ];
            };
          };
        };
      in
      lib.any (lib.hasInfix "org.freedesktop.secrets") globalWarnSystem.config.warnings
      && lib.any (lib.hasInfix "packages.codex.policy.dbus") pkgWarnSystem.config.warnings
      && !(lib.any (lib.hasInfix "org.freedesktop.secrets") wildcardSystem.config.warnings);

    # Package with only policy.secrets emits its package policy file.
    assert
      let
        json =
          builtins.fromJSON
            system.config.environment.etc."agent-sandbox/packages/secrets-only.json".text;
        system = mkNixosSystem {
          agent-sandbox = {
            gates = {
              filesystem.enable = true;
              resources.enable = true;
            };

            packages = [
              {
                package = pkgs.hello;
                name = "secrets-only";

                policy.secrets.allow = [
                  {
                    access = "read";
                    label = "My API Key";
                    partition = "host";
                  }
                ];
              }
            ];

            policy.dbus.enable = true;
          };
        };
      in
      failedModuleMessages system == [ ]
      &&
        json.secrets == {
          allow = [
            {
              access = "read";
              collection = "default";
              label = "My API Key";
              partition = "host";
            }
          ];

          deny = [ ];
        };
    true;
  clockPauseKernelVersionMessage = "agent-sandbox.policy.pauseClockWhileFrozen requires Linux 6.18 or newer (boot.kernelPackages)";
  clockPauseNetworkMessage = "agent-sandbox.policy.pauseClockWhileFrozen requires network.enable (agent-sandbox-enter creates the time namespace)";
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
  proxyClientIdentitiesMessage = "agent-sandbox HTTP proxy upstreamClientIdentitiesFile must use an absolute path";
  proxyCredentialsMessage = "agent-sandbox HTTP proxy CA certificate and key must be supplied together and use absolute paths";
  proxyGidMessage = "agent-sandbox.network.httpProxy.gid must be nonzero when explicitly configured";
  proxyNetworkMessage = "agent-sandbox.network.httpProxy.enable requires network.enable";
  proxyRulesMessage = "agent-sandbox.network.httpProxy.declarativeAllow/declarativeDeny require httpProxy.enable (configured URLs: https://api.example.com/v1)";
  resourceGateMessage = "agent-sandbox.gates.resources.enable requires gates.filesystem.enable";
  secretsHostSelectorMessage = "agent-sandbox host secret allow rules must specify at least one attribute or a label";
  secretsRequireDbusMessage = "agent-sandbox.policy.secrets rules require agent-sandbox.policy.dbus.enable = true";
  secretsReservedAttrMessage = "agent-sandbox secret rule attributes must not use reserved `agent-sandbox:` prefix";
  socketPathMessage = "agent-sandbox.policy.socketPath must not be inside /run/agent-sandbox/shared";
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
          upstreamClientIdentitiesFile = "/run/secrets/proxy-identities.json";
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

            secrets = {
              allow = [
                {
                  access = "all";
                  comment = "omp own partition";
                  partition = "own_package";
                }
              ];

              deny = [
                {
                  access = "delete";
                  partition = "host";
                }
              ];
            };

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

        secrets = {
          declarativeAllow = [
            {
              access = "read";
              attributes.service = "gh:github.com";
              comment = "shared GitHub CLI token";
              partition = "host";
            }
          ];

          declarativeDeny = [
            {
              access = "delete";
              collection = "*";
              partition = "host";
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
