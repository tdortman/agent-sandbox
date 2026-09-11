{
  lib,
  pkgs,
  inputs,
  ...
}:
rec {
  baseNode = {
    boot.kernelParams = [ "audit=0" ];
    environment.etc."agent-sandbox-test/hidden-file".text = "hidden file marker\n";
    networking.firewall.enable = false;
    nixpkgs.overlays = lib.mkForce [ ];

    systemd.tmpfiles.rules = [
      "d /home/user/sandbox-readwrite 0755 sandbox users -"
      "d /home/user/sandbox-hidden-dir 0755 sandbox users -"
      "d /home/user/sandbox-cwd 0755 sandbox users -"
      "f /home/user/sandbox-home-readonly 0666 sandbox users - home-readonly-marker"
      "d /var/lib/agent-sandbox-test 0755 root root -"
      "d /var/lib/agent-sandbox-test/readonly-dir 0777 root root -"
      "f /var/lib/agent-sandbox-test/readonly-dir/marker 0666 root root - readonly-dir-marker"
      "f /var/lib/agent-sandbox-test/readonly-file 0666 root root - readonly-file-marker"
      "f /var/lib/agent-sandbox-test/readwrite-file 0644 sandbox users - original"
      "f /var/lib/agent-sandbox-test/dynamic-read 0666 sandbox users - dynamic-read-marker"
      "f /var/lib/agent-sandbox-test/dynamic-write 0666 sandbox users - original"
      "f /var/lib/agent-sandbox-test/dynamic-denied 0666 sandbox users - denied-marker"
      "f /var/lib/agent-sandbox-test/dynamic-unlisted 0666 sandbox users - unlisted-marker"
      "d /var/lib/agent-sandbox-test/dynamic-mutations 0777 sandbox users -"
      "d /var/lib/agent-sandbox-test/dynamic-mutations/denied 0777 sandbox users -"
      "f /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret 0666 sandbox users - denied-mutation"
      "d /var/lib/agent-sandbox-test/dbus-runtime 0700 sandbox users -"
      "f /var/lib/agent-sandbox-test/hidden-file 0644 root root - hidden-file-marker"
      "f /home/user/sandbox-hidden-dir/marker 0644 sandbox users - hidden-dir-marker"
      "f /home/user/sandbox-cwd/marker 0644 sandbox users - cwd-marker"
      "c /dev/agent-sandbox-test-device 0666 root root - 1:5"
      "c /dev/agent-sandbox-denied-device 0666 root root - 1:5"
      "d /run/agent-sandbox-test-runtime 0777 root root -"
      "f /run/agent-sandbox-test-runtime/marker 0666 root root - runtime-readonly-marker"
      "d /var/lib/agent-sandbox-test/global-readonly-dir 0777 root root -"
      "f /var/lib/agent-sandbox-test/global-readonly-dir/marker 0666 root root - global-readonly-dir-marker"
      "d /var/lib/agent-sandbox-test/global-readwrite-dir 0777 sandbox users -"
      "f /var/lib/agent-sandbox-test/global-readonly-file 0666 root root - global-readonly-file-marker"
      "f /var/lib/agent-sandbox-test/global-readwrite-file 0666 sandbox users - original"
      "d /home/user/.snapshots 0755 sandbox users -"
      "f /home/user/.snapshots/marker 0644 sandbox users - snapshot-marker"
      "d /home/.snapshots 0755 root root -"
      "f /home/.snapshots/marker 0644 root root - snapshot-marker"
      "d /home/user/agent-sandbox-pkg-link-target 0755 sandbox users -"
      "f /var/lib/agent-sandbox-test/pkg-allowed-marker 0666 sandbox users - pkg-allowed-marker"
      "f /var/lib/agent-sandbox-test/pkg-denied-marker 0666 sandbox users - pkg-denied-marker"
      "f /var/lib/agent-sandbox-test/pkg-ext-marker 0666 sandbox users - pkg-ext-marker"
      "f /var/lib/agent-sandbox-test/pkg-global-marker 0666 sandbox users - pkg-global-marker"
    ];

    users.users.sandbox = testUser;

    virtualisation = {
      cores = 2;
      memorySize = 2048;
    };
  };

  commonExtraPkgs = with pkgs; [
    coreutils
    dbus
    socat
    sudo
    util-linux
  ];

  dbusPolicy = mkPolicy "dbus" {
    dbus = ''
      {
        "allow": [
          {
            "target": {
              "bus": "session",
              "destination": "*",
              "object_path": "**",
              "interface": "org.freedesktop.DBus.Introspectable",
              "member": "Introspect",
              "message_kind": "method_call",
              "signature": "",
              "fd_metadata": []
            },
            "comment": "global"
          },
          {
            "target": {
              "bus": "session",
              "destination": ":*",
              "object_path": "/org/freedesktop/DBus",
              "interface": "org.freedesktop.DBus",
              "member": "NameAcquired",
              "message_kind": "signal",
              "signature": "s",
              "fd_metadata": []
            },
            "comment": "global"
          }
        ],
        "deny": []
      }
    '';

    resources = ''
      {
        "allow": [
          { "kind": "unix_socket", "path": "/var/lib/agent-sandbox-test/dbus-runtime", "access": "connect" },
          { "kind": "unix_socket", "path": "/var/lib/agent-sandbox-test/dbus-runtime", "access": "send" }
        ],
        "deny": []
      }
    '';
  };

  directNetworkPackages = [
    (mkCurl "sandbox-direct-curl" {
      extraPkgs = commonExtraPkgs;
    })

    (mkBash "sandbox-direct-bash" {
      extraPkgs = commonExtraPkgs ++ [ pkgs.curl ];
    })
  ];

  dynamicPackages = [
    (mkBash "sandbox-dynamic-bash" {
      extraPkgs = commonExtraPkgs ++ [ pkgs.python3 ];

      hiddenPaths = [
        "/etc/agent-sandbox-test/hidden-file"
        "/var/lib/agent-sandbox-test/hidden-file"
        "~/sandbox-hidden-dir"
      ];
    })

    (mkCurl "sandbox-dynamic-curl" {
      extraPkgs = commonExtraPkgs;
      hiddenPaths = [ "/var/lib/agent-sandbox-test/hidden-file" ];
    })
  ];

  dynamicPolicy = mkPolicy "dynamic" {
    filesystem = ''
      {
        "allow": [
          { "path": "/var/lib/agent-sandbox-test/dynamic-read", "access": "read" },
          { "path": "/var/lib/agent-sandbox-test/dynamic-write", "access": "all" },
          { "path": "/var/lib/agent-sandbox-test/dynamic-denied", "access": "all" },
          { "path": "/var/lib/agent-sandbox-test/dynamic-mutations", "access": "all" }
        ],
        "deny": [
          { "path": "/var/lib/agent-sandbox-test/dynamic-denied", "access": "all" },
          { "path": "/var/lib/agent-sandbox-test/dynamic-mutations/denied", "access": "all" }
        ]
      }
    '';
  };

  emptyPolicySection = ''{ "allow": [], "deny": [] }'';

  httpServer =
    {
      port,
      address ? null,
      certificate ? null,
      privateKey ? null,
      serviceName ? "http",
    }:
    {
      name = "agent-sandbox-vm-${serviceName}-${toString port}";

      value = {
        serviceConfig = {
          ExecStart = lib.escapeShellArgs (
            [
              "${pkgs.python3}/bin/python"
              httpServerScript
              (toString port)
            ]
            ++ lib.optional (address != null) address
            ++ lib.optionals (certificate != null) [
              certificate
              privateKey
            ]
          );

          Restart = "on-failure";
          User = "sandbox";
        };

        wantedBy = [ "multi-user.target" ];
      };
    };

  httpServerScript = pkgs.writeText "agent-sandbox-vm-http.py" ''
    import sys
    import socket
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def respond(self, body):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                first = b"data: first\n\n"
                self.wfile.write(f"{len(first):X}\r\n".encode() + first + b"\r\n")
                self.wfile.flush()
                time.sleep(5)
                second = b"data: second\n\n"
                self.wfile.write(f"{len(second):X}\r\n".encode() + second + b"\r\n0\r\n\r\n")
                self.wfile.flush()
                return
            bodies = {
                "/readonly-file": b"readonly-file-marker\n",
                "/allowed": b"allowed-get\n",
                "/denied": b"denied-get\n",
                "/unlisted": b"unlisted-get\n",
            }
            if path == "/doh-ech":
                self.doh(False)
                return
            if path == "/doh-dnssec":
                self.doh(True)
                return
            if path not in bodies:
                self.send_error(404)
                return
            self.respond(bodies[path])

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            if path == "/doh-ech":
                self.doh(False)
            elif path == "/doh-dnssec":
                self.doh(True)
            else:
                self.respond(b"post-ok\n")

        def doh(self, dnssec):
            import struct
            flags = 0x8180 | (0x20 if dnssec else 0)
            question = b"\x07example\x04test\x00" + struct.pack(">HH", 65, 1)
            svcparams = struct.pack(">HH", 5, 6) + b"\x00\x04\x01\x02\x03\x04"
            rdata = struct.pack(">H", 1) + b"\x00" + svcparams
            answer = b"\xc0\x0c" + struct.pack(">HHIH", 65, 1, 300, len(rdata)) + rdata
            packet = struct.pack(">HHHHHH", 0x1234, flags, 1, 1, 0, 0) + question + answer
            self.send_response(200)
            self.send_header("Content-Type", "application/dns-message")
            self.send_header("Content-Length", str(len(packet)))
            self.end_headers()
            self.wfile.write(packet)

    class IPv6ThreadingHTTPServer(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    if len(sys.argv) == 3:
        server = IPv6ThreadingHTTPServer((sys.argv[2], int(sys.argv[1])), Handler)
    else:
        server = ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler)
    if len(sys.argv) == 4:
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(sys.argv[2], sys.argv[3])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
  '';

  httpServers = specs: {
    systemd.services = lib.listToAttrs (map httpServer specs);
  };

  # Install a store path as a policy file owned by the sandbox user before
  # policyd starts, optionally symlinking a second path to it. The symlink
  # support lets per-package extension files exercise the wrapper's symlink
  # protection end to end.
  installHomePolicy =
    serviceName:
    {
      content,
      path,
      symlink ? null,
    }:
    {
      systemd.services."agent-sandbox-vm-${serviceName}" = {
        before = [ "agent-sandbox-policy.service" ];
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };

        script = ''
          install -d -o sandbox -g users "$(dirname ${lib.escapeShellArg path})"
          install -o sandbox -g users ${content} ${lib.escapeShellArg path}
          ${lib.optionalString (symlink != null) ''
            install -d -o sandbox -g users "$(dirname ${lib.escapeShellArg symlink})"
            ln -sf ${lib.escapeShellArg path} ${lib.escapeShellArg symlink}
          ''}
        '';
      };
    };

  installPolicy =
    policy:
    installHomePolicy "policy" {
      content = policy;
      path = "/home/user/.config/agent-sandbox/policy.json";
    };

  loopbackPorts = {
    tcpPorts = [
      18089
      18090
    ];

    udpPorts = [
      18092
      18093
    ];
  };

  loopbackServices = {
    agent-sandbox-vm-loopback-host = {
      serviceConfig = {
        ExecStart = lib.escapeShellArgs [
          "${pkgs.python3}/bin/python"
          "-m"
          "http.server"
          "18089"
          "--bind"
          "127.0.0.1"
        ];

        Restart = "on-failure";
        User = "sandbox";
      };

      wantedBy = [ "multi-user.target" ];
    };

    agent-sandbox-vm-loopback-sandbox = {
      after = [ "agent-sandbox-netns.service" ];
      requires = [ "agent-sandbox-netns.service" ];

      serviceConfig = {
        ExecStart = lib.escapeShellArgs [
          "${pkgs.python3}/bin/python"
          "-m"
          "http.server"
          "18090"
          "--bind"
          "127.0.0.1"
        ];

        NetworkNamespacePath = "/run/netns/agent-sandbox";
        Restart = "on-failure";
        User = "sandbox";
      };

      wantedBy = [ "multi-user.target" ];
    };

    agent-sandbox-vm-loopback-udp-host = {
      serviceConfig = {
        ExecStart = "${pkgs.socat}/bin/socat UDP4-RECVFROM:18092,bind=127.0.0.1,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
        Restart = "on-failure";
        User = "sandbox";
      };

      wantedBy = [ "multi-user.target" ];
    };

    agent-sandbox-vm-loopback-udp-sandbox = {
      after = [ "agent-sandbox-netns.service" ];
      requires = [ "agent-sandbox-netns.service" ];

      serviceConfig = {
        ExecStart = "${pkgs.socat}/bin/socat UDP4-RECVFROM:18093,bind=127.0.0.1,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
        NetworkNamespacePath = "/run/netns/agent-sandbox";
        Restart = "on-failure";
        User = "sandbox";
      };

      wantedBy = [ "multi-user.target" ];
    };

    agent-sandbox-vm-loopback-udp6-host = {
      after = [ "agent-sandbox-loopback.service" ];
      requires = [ "agent-sandbox-loopback.service" ];

      serviceConfig = {
        ExecStart = "${pkgs.socat}/bin/socat UDP6-RECVFROM:18092,bind=[::1],fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
        Restart = "on-failure";
        User = "sandbox";
      };

      wantedBy = [ "multi-user.target" ];
    };

    agent-sandbox-vm-loopback-udp6-sandbox = {
      after = [ "agent-sandbox-loopback.service" ];
      requires = [ "agent-sandbox-loopback.service" ];

      serviceConfig = {
        ExecStart = "${pkgs.socat}/bin/socat UDP6-RECVFROM:18093,bind=[::1],fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
        NetworkNamespacePath = "/run/netns/agent-sandbox";
        Restart = "on-failure";
        User = "sandbox";
      };

      wantedBy = [ "multi-user.target" ];
    };

    agent-sandbox-vm-loopback6-host = {
      after = [ "agent-sandbox-loopback.service" ];
      requires = [ "agent-sandbox-loopback.service" ];

      serviceConfig = {
        ExecStart = lib.escapeShellArgs [
          "${pkgs.python3}/bin/python"
          "-m"
          "http.server"
          "18089"
          "--bind"
          "::1"
        ];

        Restart = "on-failure";
        User = "sandbox";
      };

      wantedBy = [ "multi-user.target" ];
    };

    agent-sandbox-vm-loopback6-sandbox = {
      after = [ "agent-sandbox-loopback.service" ];
      requires = [ "agent-sandbox-loopback.service" ];

      serviceConfig = {
        ExecStart = lib.escapeShellArgs [
          "${pkgs.python3}/bin/python"
          "-m"
          "http.server"
          "18090"
          "--bind"
          "::1"
        ];

        NetworkNamespacePath = "/run/netns/agent-sandbox";
        Restart = "on-failure";
        User = "sandbox";
      };

      wantedBy = [ "multi-user.target" ];
    };
  };

  mkBash =
    name: options:
    options
    // {
      package = pkgs.writeShellScriptBin name ''
        exec ${lib.getExe pkgs.bashInteractive} "$@"
      '';

      binary = name;
    };

  mkCurl =
    name: options:
    options
    // {
      package = pkgs.writeShellScriptBin name ''
        exec ${lib.getExe (pkgs.curl.override { http3Support = true; })} "$@"
      '';

      binary = name;
    };

  mkPolicy =
    name:
    {
      dbus ? emptyPolicySection,
      filesystem ? emptyPolicySection,
      resources ? emptyPolicySection,
      sudo ? emptyPolicySection,
    }:
    pkgs.writeText "agent-sandbox-vm-${name}-policy.json" ''
      {
        "network": { "direct": { "allow": [], "deny": [] } },
        "sudo": ${sudo},
        "filesystem": ${filesystem},
        "resources": ${resources},
        "dbus": ${dbus}
      }
    '';

  module = ../../modules/nixos/agent-sandbox;

  packageExtension = pkgs.writeText "agent-sandbox-vm-pkg-extension.json" ''
    {
      "filesystem": {
        "allow": [ { "path": "/var/lib/agent-sandbox-test/pkg-ext-marker", "access": "read" } ],
        "deny": []
      }
    }
  '';

  packagePolicy = mkPolicy "package" {
    filesystem = ''
      {
        "allow": [ { "path": "/var/lib/agent-sandbox-test/pkg-global-marker", "access": "read" } ],
        "deny": []
      }
    '';
  };

  proxyNetworkPackages = [
    (mkCurl "sandbox-proxy-curl" {
      extraPkgs = commonExtraPkgs;
    })

    (mkBash "sandbox-proxy-bash" {
      extraPkgs = commonExtraPkgs ++ [
        (pkgs.curl.override { http3Support = true; })
        pkgs.python3
      ];
    })
  ];

  proxyNode =
    lib.recursiveUpdate
      (
        baseNode
        // (httpServers [
          { port = 8008; }
          { port = 8080; }
          {
            certificate = "${tlsFixture}/server-cert.pem";
            port = 8443;
            privateKey = "${tlsFixture}/server-key.pem";
            serviceName = "https";
          }
        ])
      )
      {
        imports = [ module ];

        agent-sandbox = {
          enable = true;
          gates.syscalls.enable = true;

          network = {
            enable = true;

            declarativeAllow = [
              {
                host = "169.254.100.1";
                port = 18082;
              }
            ];

            declarativeDeny = [
              {
                host = "169.254.100.1";
                port = 18083;
              }
            ];

            dnsForwardTarget = "169.254.100.1:5353";

            httpProxy = {
              enable = true;
              caCertificateFile = "${tlsFixture}/ca-cert.pem";
              caPrivateKeyFile = "${tlsFixture}/ca-key.pem";

              declarativeAllow = [
                {
                  methods = [ "GET" ];
                  url = "http://169.254.100.1:8008/allowed";
                }
                {
                  methods = [ "GET" ];
                  url = "http://169.254.100.1:8080/allowed";
                }
                {
                  methods = [ "GET" ];
                  url = "http://169.254.100.1:8008/stream";
                }
                {
                  methods = [ "GET" ];
                  url = "https://169.254.100.1:8443/allowed";
                }
                {
                  methods = [ "GET" ];
                  url = "https://h3-allowed.test:443/allowed";
                }
                {
                  methods = [ "GET" ];
                  url = "https://h3-allowed-v6.test:443/allowed";
                }
                {
                  allMethods = true;
                  url = "http://169.254.100.1:8008/doh-ech";
                }
                {
                  allMethods = true;
                  url = "http://169.254.100.1:8008/doh-dnssec";
                }
                {
                  methods = [ "GET" ];
                  url = "https://allowed.test:8443/allowed";
                }
              ];

              declarativeDeny = [
                {
                  allMethods = true;
                  url = "http://169.254.100.1:8008/denied";
                }
                {
                  allMethods = true;
                  url = "https://169.254.100.1:8443/denied";
                }
                {
                  allMethods = true;
                  url = "https://h3-denied.test:443/denied";
                }
              ];

              http3 = {
                enable = true;
                altUdpPorts = [ 4444 ];
              };

              upstreamAllowCidrs = [
                "169.254.100.1/32"
                "fd00:dead:beef::1/128"
              ];
            };

            loopback = loopbackPorts;
            vethHost = "asbx-test-host";
            vethNetns = "asbx-test-ns";
          };

          packages = proxyNetworkPackages;

          policy = {
            interactiveApproval = false;
            uiBackend = "none";
          };
        };

        networking.firewall.interfaces.asbx-test-host = {
          allowedTCPPorts = [
            8008
            8080
            8443
          ];

          allowedUDPPorts = [
            443
            4444
          ];
        };

        systemd.services = loopbackServices // {
          agent-sandbox-vm-dns = {
            after = [ "agent-sandbox-netns.service" ];
            requires = [ "agent-sandbox-netns.service" ];
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = lib.escapeShellArgs [
                "${pkgs.dnsmasq}/bin/dnsmasq"
                "--keep-in-foreground"
                "--no-resolv"
                "--no-hosts"
                "--bind-interfaces"
                "--listen-address=169.254.100.1"
                "--port=5353"
                "--user=sandbox"
                "--address=/allowed.test/169.254.100.1"
                "--address=/denied.test/169.254.100.1"
                "--address=/h3-allowed.test/169.254.100.1"
                "--address=/h3-allowed-v6.test/fd00:dead:beef::1"
                "--address=/h3-denied.test/169.254.100.1"
              ];

              Restart = "on-failure";
            };
          };

          agent-sandbox-vm-h3-http = {
            description = "HTTP/3 origin for the sandbox e2e check";
            after = [ "network.target" ];
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
              CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

              ExecStart = lib.escapeShellArgs [
                "${sandboxPkg}/bin/h3-origin"
                "--address"
                "::"
                "--port"
                "443"
                "--certificate"
                "${tlsFixture}/server-cert.pem"
                "--private-key"
                "${tlsFixture}/server-key.pem"
                "--alt-svc-file"
                "/var/lib/h3-origin/alt-svc"
                "--log"
                "/var/log/h3-origin.log"
              ];

              Restart = "on-failure";
              StateDirectory = "h3-origin";
            };

            preStart = ''
              echo -n 169.254.100.1:4444 > /var/lib/h3-origin/alt-svc
            '';
          };

          agent-sandbox-vm-udp-18082 = {
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = "${pkgs.socat}/bin/socat UDP4-RECVFROM:18082,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
              Restart = "on-failure";
              User = "sandbox";
            };
          };

          agent-sandbox-vm-udp-18083 = {
            wantedBy = [ "multi-user.target" ];

            serviceConfig = {
              ExecStart = "${pkgs.socat}/bin/socat UDP4-RECVFROM:18083,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
              Restart = "on-failure";
              User = "sandbox";
            };
          };
        };
      };

  resourceApprovalPolicy = mkPolicy "resource-approval" {
    resources = ''
      {
        "allow": [],
        "deny": [
          { "kind": "unix_socket", "path": "/var/run/nscd/socket", "access": "connect" }
        ]
      }
    '';
  };

  resourcePackages = [
    (mkBash "sandbox-resource-bash" {
      extraPkgs = commonExtraPkgs;
    })
  ];

  resourcePolicy = mkPolicy "resource" {
    resources = ''
      {
        "allow": [
          { "kind": "unix_socket", "path": "/run/agent-sandbox-test/echo.sock", "access": "connect" },
          { "kind": "unix_socket", "path": "/run/agent-sandbox-test/echo.sock", "access": "send" },
          { "kind": "device", "path": "/dev/agent-sandbox-test-device", "access": "open_read" }
        ],
        "deny": []
      }
    '';
  };

  sandboxPkg = inputs.self.packages.${pkgs.stdenv.hostPlatform.system}.agent-sandbox;

  staticPackages = [
    (mkBash "sandbox-static-bash" {
      devicePaths = [ "/dev/agent-sandbox-test-device" ];
      exposeWorkingDirectory = true;
      extraPkgs = commonExtraPkgs;
      readonlyDirs = [ "/var/lib/agent-sandbox-test/readonly-dir" ];

      readonlyFiles = [
        "/var/lib/agent-sandbox-test/readonly-file"
        "~/sandbox-home-readonly"
      ];

      readwriteDirs = [ "~/sandbox-readwrite" ];
      readwriteFiles = [ "/var/lib/agent-sandbox-test/readwrite-file" ];
      unsafeAliasPrefix = "unwrapped-";
    })

    (mkBash "sandbox-static-options-bash" {
      blockEnvVars = [ "CUSTOM_SECRET" ];

      extraBwrapArgs = [
        "--setenv"
        "AGENT_SANDBOX_EXTRA_BWRAP"
        "covered"
      ];

      extraPkgs = commonExtraPkgs;
      runtimeReadonlyDirs = [ "/run/agent-sandbox-test-runtime" ];
    })

    (mkBash "sandbox-static-no-cwd-bash" {
      exposeWorkingDirectory = false;
      extraPkgs = commonExtraPkgs;
      runtimeReadonlyDirs = [ ];
    })

    (mkCurl "sandbox-static-curl" {
      extraPkgs = commonExtraPkgs;
    })

    {
      package = pkgs.writeShellScriptBin "sandbox-inferred-binary" ''
        printf 'inferred-binary\n'
      '';

      extraPkgs = commonExtraPkgs;
    }

    (mkBash "sandbox-wrapping-bash" {
      extraPkgs = commonExtraPkgs;
      replaceOriginalBinary = false;
    })
  ];

  sudoApprovePackages = [
    (mkBash "sandbox-sudo-approve-bash" {
      extraPkgs = commonExtraPkgs;
      readonlyDirs = [ "~/.config/agent-sandbox" ];
    })
  ];

  sudoDenyPackages = [
    (mkBash "sandbox-sudo-deny-bash" {
      extraPkgs = commonExtraPkgs;
    })
  ];

  sudoPolicy = mkPolicy "sudo" {
    sudo = ''
      {
        "allow": [ { "argv": [ "id" ], "comment": "VM elevation contract" } ],
        "deny": []
      }
    '';
  };

  testUser = {
    extraGroups = [ "dialout" ];
    group = "users";
    home = "/home/user";
    isNormalUser = true;
    linger = true;
    uid = 1000;
  };

  tlsFixture =
    pkgs.runCommand "agent-sandbox-vm-tls-fixture" { nativeBuildInputs = [ pkgs.openssl ]; }
      ''
        mkdir -p "$out"

        openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
          -subj '/CN=agent-sandbox VM test CA' \
          -addext 'basicConstraints=critical,CA:true,pathlen:1' \
          -addext 'keyUsage=critical,keyCertSign,cRLSign' \
          -keyout "$out/ca-key.pem" -out "$out/ca-cert.pem" >/dev/null 2>&1

        openssl req -new -newkey rsa:2048 -sha256 -nodes \
          -subj '/CN=169.254.100.1' \
          -keyout "$out/server-key.pem" -out "$out/server.csr" >/dev/null 2>&1

        cat > server.ext <<'EOF'
        basicConstraints=critical,CA:false
        keyUsage=critical,digitalSignature,keyEncipherment
        extendedKeyUsage=serverAuth
        subjectAltName=IP:169.254.100.1,IP:fd00:dead:beef::1,DNS:h3-allowed.test,DNS:h3-allowed-v6.test,DNS:h3-denied.test
        EOF

        openssl x509 -req -sha256 -days 3650 \
          -in "$out/server.csr" \
          -CA "$out/ca-cert.pem" -CAkey "$out/ca-key.pem" -CAcreateserial \
          -extfile server.ext -out "$out/server-cert.pem" >/dev/null 2>&1
        rm "$out/server.csr" "$out/ca-cert.srl"
      '';
}
