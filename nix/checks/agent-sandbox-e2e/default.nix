{
  lib,
  pkgs,
  inputs,
  ...
}:
let
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

        systemd.services = {
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
  vmTest = pkgs.testers.runNixOSTest (_: {
    name = "agent-sandbox-e2e";
    node.specialArgs = { inherit inputs; };

    nodes = {
      package =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (installPolicy packagePolicy) (
            lib.recursiveUpdate
              (installHomePolicy "pkg-extension" {
                content = packageExtension;
                path = "/home/user/agent-sandbox-pkg-link-target/extension.json";
                symlink = "/home/user/.config/agent-sandbox/packages/sandbox-pkg-allowed-bash.json";
              })
              {
                imports = [ module ];

                agent-sandbox = {
                  enable = true;
                  gates.filesystem.enable = true;

                  packages = [
                    (mkBash "sandbox-pkg-allowed-bash" {
                      extraPkgs = commonExtraPkgs;

                      policy.filesystem = {
                        allow = [
                          {
                            access = "read";
                            path = "/var/lib/agent-sandbox-test/pkg-allowed-marker";
                          }
                        ];

                        deny = [
                          {
                            access = "all";
                            path = "/var/lib/agent-sandbox-test/pkg-denied-marker";
                          }
                        ];
                      };
                    })

                    (mkBash "sandbox-pkg-other-bash" {
                      extraPkgs = commonExtraPkgs;

                      policy.filesystem.deny = [
                        {
                          access = "all";
                          path = "/var/lib/agent-sandbox-test/pkg-global-marker";
                        }
                      ];
                    })
                  ];

                  policy = {
                    interactiveApproval = false;
                    uiBackend = "none";
                  };
                };
              }
          )
        );

      approval =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (httpServers [ { port = 8008; } ]) {
            imports = [ module ];

            agent-sandbox = {
              enable = true;

              network = {
                enable = true;
                dnsForwardTarget = "169.254.100.1:5353";

                httpProxy = {
                  enable = true;
                  caCertificateFile = "${tlsFixture}/ca-cert.pem";
                  caPrivateKeyFile = "${tlsFixture}/ca-key.pem";
                  upstreamAllowCidrs = [ "169.254.100.1/32" ];
                };
              };

              packages = [
                (mkBash "sandbox-approve-bash" {
                  extraPkgs = commonExtraPkgs ++ [ pkgs.curl ];
                })
                (mkBash "sandbox-approve-other-bash" {
                  extraPkgs = commonExtraPkgs ++ [ pkgs.curl ];
                })
              ];

              # Pending requests are recorded but no UI is spawned; the
              # scenario resolves them with agent-sandbox-approve.
              policy.uiBackend = "none";
            };

            networking.firewall.interfaces.asbx-test-host.allowedTCPPorts = [ 8008 ];

            systemd.services.agent-sandbox-vm-dns = {
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
                ];

                Restart = "on-failure";
              };
            };
          }
        );

      dbus =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (installPolicy dbusPolicy) {
            imports = [ module ];

            agent-sandbox = {
              enable = true;

              gates = {
                filesystem.enable = true;
                resources.enable = true;
              };

              packages = [
                (mkBash "sandbox-dbus-bash" {
                  extraPkgs = commonExtraPkgs;
                })
              ];

              policy = {
                dbus = {
                  enable = true;

                  declarativeAllow = [
                    {
                      comment = "VM module serialization allow";

                      target = {
                        bus = "session";
                        destination = "org.freedesktop.DBus";
                        interface = "org.freedesktop.DBus";
                        member = "ListNames";
                        messageKind = "method_call";
                        objectPath = "/org/freedesktop/DBus";
                        signature = "";
                      };
                    }
                  ];

                  declarativeDeny = [
                    {
                      comment = "VM module serialization deny";

                      target = {
                        bus = "session";
                        destination = "org.freedesktop.DBus";
                        interface = "org.freedesktop.DBus";
                        member = "GetId";
                        messageKind = "method_call";
                        objectPath = "/org/freedesktop/DBus";
                        signature = "";
                      };
                    }
                  ];

                  socketDirectory = "/var/lib/agent-sandbox-test/dbus-runtime";
                  upstreamAddress = "unix:path=/run/user/1000/bus";
                };

                interactiveApproval = false;
                uiBackend = "none";
              };
            };

            services.dbus.enable = true;
          }
        );

      direct =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate
            (httpServers (
              (map (port: { inherit port; }) [
                18080
                18081
                18086
                18087
                18088
              ])
              ++ (map
                (port: {
                  inherit port;
                  address = "::";
                  serviceName = "http6";
                })
                [
                  18084
                  18085
                ]
              )
            ))
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
                      port = 18080;
                    }
                    {
                      host = "169.254.100.1";
                      port = 18082;
                    }
                    {
                      host = "fd00:dead:beef::1";
                      port = 18084;
                    }
                    {
                      host = "allowed.test";
                      port = 18086;
                    }
                  ];

                  declarativeDeny = [
                    {
                      host = "169.254.100.1";
                      port = 18081;
                    }
                    {
                      host = "169.254.100.1";
                      port = 18083;
                    }
                    {
                      host = "fd00:dead:beef::1";
                      port = 18085;
                    }
                    {
                      host = "denied.test";
                      port = 18087;
                    }
                  ];

                  dnsForwardTarget = "169.254.100.1:5353";
                };

                packages = directNetworkPackages;

                policy = {
                  interactiveApproval = false;
                  uiBackend = "none";
                };
              };

              systemd.services = {
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
                    ];

                    Restart = "on-failure";
                  };
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
            }
        );

      dynamic =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (installPolicy dynamicPolicy) {
            imports = [ module ];

            agent-sandbox = {
              enable = true;
              gates.filesystem.enable = true;
              packages = dynamicPackages;

              policy = {
                exportedNix = "/var/lib/agent-sandbox/exported-policy.nix";
                interactiveApproval = false;
                uiBackend = "none";
              };
            };
          }
        );

      proxy = proxyNode;

      resource =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (installPolicy resourcePolicy) {
            imports = [ module ];

            agent-sandbox = {
              enable = true;

              gates = {
                filesystem.enable = true;
                resources.enable = true;
              };

              packages = resourcePackages;

              policy = {
                dbus.enable = false;
                interactiveApproval = false;
                uiBackend = "none";
              };
            };

            services.dbus.enable = true;

            systemd.services = {
              agent-sandbox-vm-resource-denied-server = {
                after = [ "agent-sandbox-vm-resource-server.service" ];
                requires = [ "agent-sandbox-vm-resource-server.service" ];
                wantedBy = [ "multi-user.target" ];

                serviceConfig = {
                  ExecStart = "${pkgs.socat}/bin/socat UNIX-LISTEN:/run/agent-sandbox-test/denied.sock,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
                  Restart = "on-failure";
                  User = "sandbox";
                };
              };

              agent-sandbox-vm-resource-server = {
                after = [ "agent-sandbox-vm-policy.service" ];
                wantedBy = [ "multi-user.target" ];

                serviceConfig = {
                  ExecStart = "${pkgs.socat}/bin/socat UNIX-LISTEN:/run/agent-sandbox-test/echo.sock,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
                  Restart = "on-failure";
                  RuntimeDirectory = "agent-sandbox-test";
                  User = "sandbox";
                };
              };
            };
          }
        );

      resource-approval =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (installPolicy resourceApprovalPolicy) {
            imports = [ module ];

            agent-sandbox = {
              enable = true;

              gates = {
                filesystem.enable = true;
                resources.enable = true;
              };

              packages = [
                (mkBash "sandbox-resource-approve-bash" {
                  extraPkgs = commonExtraPkgs;
                })
              ];

              policy = {
                dbus.enable = false;
                uiBackend = "none";
              };
            };

            services.dbus.enable = true;

            systemd.services.agent-sandbox-vm-resource-pending-server = {
              after = [ "agent-sandbox-vm-policy.service" ];
              wantedBy = [ "multi-user.target" ];

              serviceConfig = {
                ExecStart = "${pkgs.socat}/bin/socat UNIX-LISTEN:/run/agent-sandbox-test/pending.sock,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
                Restart = "on-failure";
                RuntimeDirectory = "agent-sandbox-test";
                User = "sandbox";
              };
            };
          }
        );

      static =
        _:
        baseNode
        // {
          imports = [ module ];

          agent-sandbox = {
            enable = true;
            packages = staticPackages;
            readonlyDirs = [ "/var/lib/agent-sandbox-test/global-readonly-dir" ];
            readonlyFiles = [ "/var/lib/agent-sandbox-test/global-readonly-file" ];
            readwriteDirs = [ "/var/lib/agent-sandbox-test/global-readwrite-dir" ];
            readwriteFiles = [ "/var/lib/agent-sandbox-test/global-readwrite-file" ];
            sudoPolicy = "deny";
            wrapping.unsafeAliasPrefix = "unwrapped-";
          };
        };

      sudo-approve =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (installPolicy sudoPolicy) {
            imports = [ module ];

            agent-sandbox = {
              enable = true;
              packages = sudoApprovePackages;

              policy = {
                interactiveApproval = false;
                uiBackend = "none";
              };

              sudoPolicy = "approve";
            };
          }
        );

      sudo-deny =
        _:
        baseNode
        // {
          imports = [ module ];

          agent-sandbox = {
            enable = true;
            packages = sudoDenyPackages;
            sudoPolicy = "deny";
          };
        };

      wrapping =
        _:
        baseNode
        // {
          imports = [ module ];

          agent-sandbox = {
            enable = true;
            packages = wrappingPackages;
            wrapping.replaceOriginalBinary = false;
          };
        };
    };

    testScript = ''
      import shlex

      def command(*args):
          return shlex.join(str(arg) for arg in args)

      def sandbox_command(node, args, *, wrapper=(), expect_success=True):
          line = command("runuser", "-u", "sandbox", "--", *wrapper, *args)
          check = node.succeed if expect_success else node.fail
          return check(line, timeout=60)

      def sandbox_shell(node, package, script, *, wrapper=(), cwd=None, env=(), expect_success=True):
          argv = [*env, package, "-c", script]
          if cwd is not None:
              argv = ["sh", "-c", f"cd {shlex.quote(cwd)} && exec {shlex.join(argv)}"]
          return sandbox_command(
              node,
              argv,
              wrapper=wrapper,
              expect_success=expect_success,
          )

      def sandbox_exec(node, package, *args, wrapper=(), expect_success=True):
          return sandbox_command(node, [package, *args], wrapper=wrapper, expect_success=expect_success)

      start_all()
      session_wrapper = (
          "env",
          "XDG_RUNTIME_DIR=/run/user/1000",
          "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
      )

      for node in [static, wrapping, dynamic, package, resource, dbus, direct, proxy, sudo_deny, sudo_approve, approval, resource_approval]:
          node.wait_for_unit("multi-user.target")

      # Static bubblewrap mounts: read-only directory/file, writable directory,
      # unlisted paths, working-directory opt-out, blocked credentials, and
      # wrapper naming.
      static.succeed("stat -c '%a %U' /var/lib/agent-sandbox-test/readwrite-file | grep -q '644 sandbox'")
      sandbox_shell(static, "sandbox-static-no-cwd-bash", "test ! -e /run/wrappers/bin/sudo")
      static.succeed("runuser -u sandbox -- test -w /var/lib/agent-sandbox-test/readwrite-file")
      sandbox_shell(static, "sandbox-static-bash", "cat /var/lib/agent-sandbox-test/readonly-file | grep -q marker")
      sandbox_shell(static, "sandbox-static-bash", "echo changed > /var/lib/agent-sandbox-test/readonly-file", expect_success=False)
      sandbox_shell(static, "sandbox-static-bash", "test -f /var/lib/agent-sandbox-test/readonly-dir/marker")
      sandbox_shell(static, "sandbox-static-bash", "touch /var/lib/agent-sandbox-test/readonly-dir/blocked", expect_success=False)
      sandbox_shell(static, "sandbox-static-bash", "test ! -e /var/lib/agent-sandbox-test/dynamic-unlisted")
      sandbox_shell(static, "sandbox-static-bash", "grep -q home-readonly-marker ~/sandbox-home-readonly")
      sandbox_shell(static, "sandbox-static-bash", "echo changed > ~/sandbox-home-readonly", expect_success=False)
      sandbox_shell(static, "sandbox-static-bash", "touch ~/sandbox-readwrite/created")
      sandbox_shell(static, "sandbox-static-bash", "test -f ~/sandbox-readwrite/created")
      sandbox_shell(static, "sandbox-static-bash", "opts=$(findmnt -no OPTIONS -T /var/lib/agent-sandbox-test/readwrite-file); [[ ,$opts, == *,rw,* ]]")
      sandbox_shell(static, "sandbox-static-bash", "printf changed > /var/lib/agent-sandbox-test/readwrite-file")
      sandbox_shell(static, "sandbox-static-bash", "grep -q changed /var/lib/agent-sandbox-test/readwrite-file")
      sandbox_shell(static, "sandbox-static-bash", "grep -q global-readonly-dir-marker /var/lib/agent-sandbox-test/global-readonly-dir/marker")
      sandbox_shell(static, "sandbox-static-bash", "touch /var/lib/agent-sandbox-test/global-readonly-dir/blocked", expect_success=False)
      sandbox_shell(static, "sandbox-static-bash", "grep -q global-readonly-file-marker /var/lib/agent-sandbox-test/global-readonly-file")
      sandbox_shell(static, "sandbox-static-bash", "printf changed >/var/lib/agent-sandbox-test/global-readonly-file", expect_success=False)
      sandbox_shell(static, "sandbox-static-bash", "touch /var/lib/agent-sandbox-test/global-readwrite-dir/created")
      sandbox_shell(static, "sandbox-static-bash", "printf changed >/var/lib/agent-sandbox-test/global-readwrite-file")
      static.succeed("test -f /var/lib/agent-sandbox-test/global-readwrite-dir/created")
      static.succeed("grep -q changed /var/lib/agent-sandbox-test/global-readwrite-file")
      sandbox_shell(
          static,
          "sandbox-static-options-bash",
          "grep -q runtime-readonly-marker /run/agent-sandbox-test-runtime/marker && test \"$AGENT_SANDBOX_EXTRA_BWRAP\" = covered && test -z \"$CUSTOM_SECRET\"",
          env=("env", "CUSTOM_SECRET=secret"),
      )
      sandbox_shell(static, "sandbox-static-options-bash", "touch /run/agent-sandbox-test-runtime/blocked", expect_success=False)
      sandbox_shell(
          static,
          "sandbox-static-bash",
          "test -z \"$AWS_SECRET_ACCESS_KEY\" && test -z \"$OPENAI_API_KEY\"",
          env=("env", "AWS_SECRET_ACCESS_KEY=secret", "OPENAI_API_KEY=secret"),
      )
      sandbox_shell(static, "sandbox-static-bash", "test -c /dev/agent-sandbox-test-device && dd if=/dev/agent-sandbox-test-device of=/dev/null bs=1 count=1 status=none")
      sandbox_shell(
          static,
          "sandbox-static-no-cwd-bash",
          'test ! -e "$PWD/marker"',
          cwd="/home/user/sandbox-cwd",
      )
      sandbox_shell(
          static,
          "sandbox-static-bash",
          'grep -q cwd-marker "$PWD/marker"',
          cwd="/home/user/sandbox-cwd",
      )
      sandbox_exec(static, "sandbox-static-curl", "--version")
      assert sandbox_command(static, [ "sandbox-inferred-binary" ]).strip() == "inferred-binary"
      sandbox_shell(static, "unwrapped-sandbox-static-bash", "printf custom-prefix")
      sandbox_shell(wrapping, "sandbox-wrapping-bash", "printf original")
      sandbox_shell(wrapping, "sandboxed-sandbox-wrapping-bash", "printf no-replacement")

      # Dynamic filesystem approval: static store access remains available,
      # unlisted host files are denied, and configured masks hide contents.
      dynamic.wait_for_unit("agent-sandbox-policy.service")
      # nfq persists the session context file during a previous sandbox run,
      # so a fresh launch always finds it present. fsmon must tolerate that:
      # reading the file after marking sandbox mounts would deadlock on its
      # own fanotify permission event, so every launch below is a regression
      # test for the second-launch hang.
      dynamic.succeed(
          "mkdir -p /run/agent-sandbox && printf '%s\\n' '{\"cwd\": \"/home/sandbox\", \"home\": \"/home/sandbox\", \"project_root\": \"/home/sandbox\"}' > /run/agent-sandbox/session-context.json"
      )
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -r /nix/store")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "grep -q dynamic-read-marker /var/lib/agent-sandbox-test/dynamic-read")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf changed >/var/lib/agent-sandbox-test/dynamic-read", expect_success=False)
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf changed > /var/lib/agent-sandbox-test/dynamic-write")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "grep -q changed /var/lib/agent-sandbox-test/dynamic-write")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "! cat /var/lib/agent-sandbox-test/dynamic-denied >/dev/null")
      # Mutation syscalls require every affected path to pass policy. Exercise
      # successful rename/link/symlink/truncate/ftruncate/unlink operations,
      # then reject each operation when either endpoint is under a deny rule.
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf mutation > /var/lib/agent-sandbox-test/dynamic-mutations/rename-source")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "mv /var/lib/agent-sandbox-test/dynamic-mutations/rename-source /var/lib/agent-sandbox-test/dynamic-mutations/renamed")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln /var/lib/agent-sandbox-test/dynamic-mutations/renamed /var/lib/agent-sandbox-test/dynamic-mutations/hardlink")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln -s renamed /var/lib/agent-sandbox-test/dynamic-mutations/symlink")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "python3 -c 'import os; path = \"/var/lib/agent-sandbox-test/dynamic-mutations/renamed\"; os.truncate(path, 2); fd = os.open(path, os.O_WRONLY); os.ftruncate(fd, 1); os.close(fd)'")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "test \"$(stat -c %s /var/lib/agent-sandbox-test/dynamic-mutations/renamed)\" = 1")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "rm /var/lib/agent-sandbox-test/dynamic-mutations/hardlink /var/lib/agent-sandbox-test/dynamic-mutations/symlink")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf blocked > /var/lib/agent-sandbox-test/dynamic-mutations/rename-denied-source")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "mv /var/lib/agent-sandbox-test/dynamic-mutations/rename-denied-source /var/lib/agent-sandbox-test/dynamic-mutations/denied/renamed", expect_success=False)
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln /var/lib/agent-sandbox-test/dynamic-mutations/renamed /var/lib/agent-sandbox-test/dynamic-mutations/denied/hardlink", expect_success=False)
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "ln -s denied/secret /var/lib/agent-sandbox-test/dynamic-mutations/symlink-to-denied", expect_success=False)
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "mv /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret /var/lib/agent-sandbox-test/dynamic-mutations/moved-from-denied", expect_success=False)
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "rm /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret", expect_success=False)
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "truncate -s 0 /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret", expect_success=False)
      dynamic.succeed("test -f /var/lib/agent-sandbox-test/dynamic-mutations/rename-denied-source")
      dynamic.succeed("test -f /var/lib/agent-sandbox-test/dynamic-mutations/denied/secret")
      dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/denied/renamed")
      dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/denied/hardlink")
      dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/symlink-to-denied")
      dynamic.succeed("test ! -e /var/lib/agent-sandbox-test/dynamic-mutations/moved-from-denied")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -c /etc/agent-sandbox-test/hidden-file")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "! cat /var/lib/agent-sandbox-test/dynamic-unlisted >/dev/null")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -c /var/lib/agent-sandbox-test/hidden-file && ! grep -q 'hidden-file-marker' /var/lib/agent-sandbox-test/hidden-file")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -d ~/sandbox-hidden-dir && test ! -e ~/sandbox-hidden-dir/marker")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "printf dynamic >/tmp/dynamic-marker")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -d ~/.snapshots && test ! -e ~/.snapshots/marker")
      sandbox_shell(dynamic, "sandbox-dynamic-bash", "test -d /home/.snapshots && test ! -e /home/.snapshots/marker")
      dynamic.succeed("${lib.getExe pkgs.jq} -e . /var/lib/agent-sandbox/exported-policy.json >/dev/null")
      dynamic.succeed("nix-instantiate --eval --strict /var/lib/agent-sandbox/exported-policy.nix >/dev/null")
      sandbox_exec(dynamic, "sandbox-dynamic-curl", "--version")
      sandbox_shell(
          dynamic,
          "sandbox-dynamic-bash",
          "test -z \"$AWS_SECRET_ACCESS_KEY\" && test -z \"$OPENAI_API_KEY\"",
          env=("env", "AWS_SECRET_ACCESS_KEY=secret", "OPENAI_API_KEY=secret"),
      )

      # Per-package policy: declarative base files, the user-writable home
      # extension (symlinked), deny-wins, cross-package isolation, and
      # in-sandbox read/write protection of the policy files.
      package.wait_for_unit("agent-sandbox-policy.service")
      package.succeed(
          "test -f /etc/agent-sandbox/packages/sandbox-pkg-allowed-bash.json && test -f /etc/agent-sandbox/packages/sandbox-pkg-other-bash.json"
      )
      # Declared base allow and deny apply without a prompt.
      sandbox_shell(package, "sandbox-pkg-allowed-bash", "grep -q pkg-allowed-marker /var/lib/agent-sandbox-test/pkg-allowed-marker")
      sandbox_shell(package, "sandbox-pkg-allowed-bash", "cat /var/lib/agent-sandbox-test/pkg-denied-marker >/dev/null", expect_success=False)
      # Cross-package isolation: the other package has no rule for the marker.
      sandbox_shell(package, "sandbox-pkg-other-bash", "cat /var/lib/agent-sandbox-test/pkg-allowed-marker >/dev/null", expect_success=False)
      # Deny-wins: the user policy allows the marker, the package deny shadows it.
      sandbox_shell(package, "sandbox-pkg-other-bash", "cat /var/lib/agent-sandbox-test/pkg-global-marker >/dev/null", expect_success=False)
      sandbox_shell(package, "sandbox-pkg-allowed-bash", "grep -q pkg-global-marker /var/lib/agent-sandbox-test/pkg-global-marker")
      # The symlinked home extension is loaded and its allow applies.
      sandbox_shell(package, "sandbox-pkg-allowed-bash", "grep -q pkg-ext-marker /var/lib/agent-sandbox-test/pkg-ext-marker")
      # The declarative base and the home extension are unreadable in-sandbox.
      sandbox_shell(package, "sandbox-pkg-allowed-bash", "cat /etc/agent-sandbox/packages/sandbox-pkg-allowed-bash.json >/dev/null", expect_success=False)
      sandbox_shell(package, "sandbox-pkg-allowed-bash", "cat ~/.config/agent-sandbox/packages/sandbox-pkg-allowed-bash.json >/dev/null", expect_success=False)
      # A write through the symlinked extension is blocked (ro-bound target).
      sandbox_shell(package, "sandbox-pkg-allowed-bash", "printf changed >> ~/.config/agent-sandbox/packages/sandbox-pkg-allowed-bash.json", expect_success=False)

      # Resource gates distinguish permitted Unix-socket connect/send and
      # device opens from denied host IPC sockets.
      resource.wait_for_unit("agent-sandbox-policy.service")
      resource.wait_for_unit("agent-sandbox-vm-resource-server.service")
      resource.wait_for_unit("agent-sandbox-vm-resource-denied-server.service")
      resource.succeed("test -S /run/agent-sandbox-test/echo.sock && test -S /run/agent-sandbox-test/denied.sock")
      resource.succeed("test -c /dev/agent-sandbox-test-device && test -c /dev/agent-sandbox-denied-device")
      sandbox_shell(resource, "sandbox-resource-bash", "printf resource-ok | socat -T 2 - UNIX-CONNECT:/run/agent-sandbox-test/echo.sock | grep -q resource-ok")
      sandbox_shell(resource, "sandbox-resource-bash", "printf blocked | socat -T 2 - UNIX-CONNECT:/run/agent-sandbox-test/denied.sock | grep -q blocked", expect_success=False)
      sandbox_shell(resource, "sandbox-resource-bash", "dd if=/dev/agent-sandbox-test-device of=/dev/null bs=1 count=1 status=none")
      sandbox_shell(resource, "sandbox-resource-bash", "dd if=/dev/agent-sandbox-denied-device of=/dev/null bs=1 count=1 status=none", expect_success=False)

      # D-Bus relay: the configured upstream overrides a bad caller address,
      # allowed ListNames succeeds, GetId is denied, and the system bus is hidden.
      dbus.wait_for_unit("agent-sandbox-policy.service")
      sandbox_shell(
          dbus,
          "sandbox-dbus-bash",
          "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -q array",
          wrapper=("env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/missing-bus"),
      )
      sandbox_shell(
          dbus,
          "sandbox-dbus-bash",
          "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Introspectable.Introspect | grep -q org.freedesktop.DBus",
          wrapper=session_wrapper,
      )
      sandbox_shell(
          dbus,
          "sandbox-dbus-bash",
          "! dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.GetId",
          wrapper=("env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"),
      )
      sandbox_shell(
          dbus,
          "sandbox-dbus-bash",
          "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.RequestName string:com.example.Sandbox uint32:0",
          wrapper=session_wrapper,
          expect_success=False,
      )
      sandbox_shell(
          dbus,
          "sandbox-dbus-bash",
          "! timeout 2 socat - UNIX-CONNECT:/run/dbus/system_bus_socket",
          wrapper=("env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"),
      )

      # Direct transport policy: declared TCP and UDP ports are reachable,
      # while denied ports with listening backends remain unreachable.
      direct.wait_for_unit("agent-sandbox-netns.service")
      direct.wait_for_unit("agent-sandbox-policy.service")
      direct.wait_for_unit("agent-sandbox-vm-dns.service")
      sandbox_shell(direct, "sandbox-direct-bash", "grep -Eq '^Seccomp_filters:[[:space:]]*[1-9][0-9]*$' /proc/self/status")
      direct.wait_for_open_port(18080)
      direct.wait_for_open_port(18081)
      direct.wait_for_unit("agent-sandbox-vm-udp-18082.service")
      direct.wait_for_unit("agent-sandbox-vm-udp-18083.service")
      direct.wait_for_unit("agent-sandbox-vm-http6-18084.service")
      direct.wait_for_unit("agent-sandbox-vm-http6-18085.service")
      direct.succeed("curl --noproxy '*' --fail --silent 'http://[::1]:18084/allowed' | grep -q allowed-get")
      direct.succeed("curl --noproxy '*' --fail --silent 'http://[::1]:18085/allowed' | grep -q allowed-get")
      direct.wait_for_open_port(18086)
      direct.wait_for_open_port(18087)
      direct.wait_for_open_port(18088)
      sandbox_shell(direct, "sandbox-direct-bash", "curl --fail --silent --show-error --max-time 15 http://169.254.100.1:18080/readonly-file | grep -q readonly-file-marker")
      sandbox_exec(direct, "sandbox-direct-curl", "--silent", "--show-error", "--max-time", "5", "http://169.254.100.1:18081/readonly-file", expect_success=False)
      sandbox_shell(direct, "sandbox-direct-bash", "printf udp-ok | timeout 5 socat - UDP4:169.254.100.1:18082 | grep -q udp-ok")
      sandbox_shell(direct, "sandbox-direct-bash", "printf blocked | timeout 3 socat - UDP4:169.254.100.1:18083 | grep -q blocked", expect_success=False)
      sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --fail --silent --show-error --max-time 15 'http://[fd00:dead:beef::1]:18084/allowed' | grep -q allowed-get")
      sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --fail --silent --show-error --max-time 5 'http://[fd00:dead:beef::1]:18085/allowed'", expect_success=False)
      sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --fail --silent --show-error --max-time 15 http://allowed.test:18086/allowed | grep -q allowed-get")
      sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --silent --show-error --max-time 5 http://denied.test:18087/denied", expect_success=False)
      sandbox_shell(direct, "sandbox-direct-bash", "curl --noproxy '*' --silent --show-error --max-time 5 http://169.254.100.1:18088/unlisted", expect_success=False)

      # Transparent HTTP(S) policy: exercise the allow, deny, TLS, and
      # streaming contracts through the transparent proxy.
      print(proxy.succeed("systemctl --no-pager --full status agent-sandbox-proxy.service agent-sandbox-proxy-route.service agent-sandbox-nfq.service agent-sandbox-dns.service agent-sandbox-netns.service agent-sandbox-policy.service agent-sandbox-proxy-firewall.service agent-sandbox-proxy-init.service || true"))
      print(proxy.succeed("systemctl --failed --no-legend || true; journalctl --no-pager -b -u agent-sandbox-proxy-route.service -u agent-sandbox-nfq.service -u agent-sandbox-dns.service -u agent-sandbox-netns.service -u agent-sandbox-policy.service || true"))
      proxy.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
      proxy.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
      proxy.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
      print(proxy.succeed("ip netns exec agent-sandbox sh -c 'ip rule show; ip route show table 51820' || true"))
      print(proxy.succeed("systemctl show --property=MainPID,ActiveState,SubState,ExecMainCode,ExecMainStatus agent-sandbox-proxy.service; systemctl --no-pager --full status agent-sandbox-proxy.service || true"))
      print(proxy.succeed("ip netns exec agent-sandbox sh -c 'cat /proc/net/tcp; cat /proc/net/tcp6'"))
      print(proxy.succeed("ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} -a list table inet agent_sandbox_proxy_tproxy"))
      proxy.wait_for_unit("user@1000.service")
      proxy.wait_for_open_port(8008)
      proxy.wait_for_open_port(8080)
      proxy.wait_for_open_port(8443)
      proxy.succeed("curl --fail --silent -X POST http://127.0.0.1:8008/allowed | grep -q post-ok")
      proxy.succeed("curl --fail --silent http://127.0.0.1:8008/unlisted | grep -q unlisted-get")
      proxy.succeed("curl --fail --silent --cacert ${tlsFixture}/ca-cert.pem https://169.254.100.1:8443/allowed | grep -q allowed-get")
      sandbox_shell(proxy, "sandbox-proxy-bash", "test \"$SSL_CERT_FILE\" = /run/agent-sandbox/proxy-ca-bundle.pem && test \"$NODE_EXTRA_CA_CERTS\" = /run/agent-sandbox/proxy-ca-bundle.pem && test -r \"$SSL_CERT_FILE\"", wrapper=session_wrapper)
      print(proxy.succeed("ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} -a list table inet agent_sandbox"))
      print(proxy.succeed("ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} -a list ruleset"))
      sandbox_shell(proxy, "sandbox-proxy-bash", "curl --fail --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed | grep -q allowed-get", wrapper=session_wrapper)
      sandbox_shell(proxy, "sandbox-proxy-bash", "curl --fail --silent --show-error --max-time 30 http://169.254.100.1:8080/allowed | grep -q allowed-get", wrapper=session_wrapper)
      sandbox_shell(proxy, "sandbox-proxy-bash", "curl --fail --silent --show-error --max-time 30 https://169.254.100.1:8443/allowed | grep -q allowed-get", wrapper=session_wrapper)
      sandbox_shell(proxy, "sandbox-proxy-bash", "timeout 3 curl --no-buffer --fail --silent --show-error 'http://169.254.100.1:8008/stream?alt=sse' | grep -q 'data: first'", wrapper=session_wrapper)
      sandbox_shell(
          proxy,
          "sandbox-proxy-bash",
          "status=$(curl --silent --show-error --max-time 15 --dump-header /tmp/proxy-denied-http.headers --output /tmp/proxy-denied-http.body --write-out '%{http_code}' http://169.254.100.1:8008/denied); test \"$status\" = 403 && grep -F -q 'x-agent-sandbox-policy: blocked' /tmp/proxy-denied-http.headers && grep -F -x -q 'blocked by agent-sandbox policy' /tmp/proxy-denied-http.body",
          wrapper=session_wrapper,
      )
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "-X", "POST", "http://169.254.100.1:8008/denied", wrapper=session_wrapper, expect_success=False)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "-X", "POST", "http://169.254.100.1:8008/allowed", wrapper=session_wrapper, expect_success=False)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "http://169.254.100.1:8008/unlisted", wrapper=session_wrapper, expect_success=False)
      sandbox_shell(
          proxy,
          "sandbox-proxy-bash",
          "status=$(curl --silent --show-error --max-time 15 --dump-header /tmp/proxy-denied-https.headers --output /tmp/proxy-denied-https.body --write-out '%{http_code}' https://169.254.100.1:8443/denied); test \"$status\" = 403 && grep -F -q 'x-agent-sandbox-policy: blocked' /tmp/proxy-denied-https.headers && grep -F -x -q 'blocked by agent-sandbox policy' /tmp/proxy-denied-https.body",
          wrapper=session_wrapper,
      )
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "-X", "POST", "https://169.254.100.1:8443/allowed", wrapper=session_wrapper, expect_success=False)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "https://169.254.100.1:8443/unlisted", wrapper=session_wrapper, expect_success=False)

      # HTTP/3 policy is enforced per decoded request over IPv4 and IPv6.
      proxy.wait_for_unit("agent-sandbox-vm-h3-http.service", timeout=120)
      sandbox_shell(
          proxy,
          "sandbox-proxy-bash",
          "python3 -c 'import socket; assert socket.getaddrinfo(\"h3-allowed.test\", 443); assert socket.getaddrinfo(\"h3-allowed-v6.test\", 443)'",
          wrapper=session_wrapper,
      )
      proxy.succeed("set +e; ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} reset counters table inet agent_sandbox_proxy_tproxy; runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus sandbox-proxy-bash -c 'curl --http3-only --cacert /run/agent-sandbox/proxy-ca-bundle.pem --fail --silent --show-error --max-time 15 https://h3-allowed.test:443/allowed | grep -q allowed-get' >/tmp/h3-allowed.log 2>&1; status=$?; cat /tmp/h3-allowed.log; ip netns exec agent-sandbox ip route get 169.254.100.1 mark 51820; ip netns exec agent-sandbox cat /proc/net/udp /proc/net/udp6; ip netns exec agent-sandbox ${lib.getExe pkgs.nftables} -a list table inet agent_sandbox_proxy_tproxy; test $status -eq 0")
      sandbox_shell(
          proxy,
          "sandbox-proxy-bash",
          "curl --http3-only --cacert /run/agent-sandbox/proxy-ca-bundle.pem --fail --silent --show-error --max-time 15 https://h3-allowed-v6.test:443/allowed | grep -q allowed-get",
          wrapper=session_wrapper,
      )
      # Raw or invalid UDP on intercepted HTTP/3 ports is rejected by the
      # proxy instead of egressing directly to the origin.
      proxy.succeed("before=$(grep -c '^datagram ' /var/log/h3-origin.log || true); set +e; runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus sandbox-proxy-bash -c 'printf blocked | timeout 3 socat - UDP4:169.254.100.1:443 | grep -q blocked' >/tmp/h3-raw-udp.log 2>&1; status=$?; set -e; cat /tmp/h3-raw-udp.log; sleep 1; after=$(grep -c '^datagram ' /var/log/h3-origin.log || true); test $status -ne 0; test \"$before\" = \"$after\"")

      proxy.succeed("before=$(grep -c '^datagram ' /var/log/h3-origin.log || true); set +e; runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus sandbox-proxy-bash -c 'printf blocked | timeout 3 socat - UDP4:169.254.100.1:4444 | grep -q blocked' >/tmp/h3-raw-alt-udp.log 2>&1; status=$?; set -e; cat /tmp/h3-raw-alt-udp.log; sleep 1; after=$(grep -c '^datagram ' /var/log/h3-origin.log || true); test $status -ne 0; test \"$before\" = \"$after\"")

      print(
          sandbox_shell(
              proxy,
              "sandbox-proxy-bash",
              "alt_svc=/tmp/h3-alt-svc-$$.cache; curl --http3-only --alt-svc \"$alt_svc\" --cacert /run/agent-sandbox/proxy-ca-bundle.pem --fail --silent --show-error --max-time 15 https://h3-allowed.test:443/allowed | grep -q allowed-get && cat \"$alt_svc\" && test -s \"$alt_svc\" && curl --http3 --alt-svc \"$alt_svc\" --cacert /run/agent-sandbox/proxy-ca-bundle.pem --fail --silent --show-error --max-time 15 https://h3-allowed.test:443/allowed | grep -q allowed-get",
              wrapper=session_wrapper,
          )
      )
      # Proxy mode gates UDP at the packet layer: new flows are queued for a
      # transport check (one prompt per host:port), then established flows
      # pass via conntrack.
      proxy.wait_for_unit("agent-sandbox-vm-udp-18082.service")
      proxy.wait_for_unit("agent-sandbox-vm-udp-18083.service")
      sandbox_shell(proxy, "sandbox-proxy-bash", "printf udp-ok | timeout 5 socat - UDP4:169.254.100.1:18082 | grep -q udp-ok", wrapper=session_wrapper)
      sandbox_shell(proxy, "sandbox-proxy-bash", "printf blocked | timeout 3 socat - UDP4:169.254.100.1:18083 | grep -q blocked", wrapper=session_wrapper, expect_success=False)
      proxy.succeed("journalctl --no-pager -b -u agent-sandbox-proxy.service | grep -F -q 'attributed alternative QUIC endpoint'")

      # The denied HTTP/3 request must complete as a clean 403 response.
      # A stream reset after the deny body would make curl exit non-zero.
      proxy.succeed("before=$(grep -F -c 'request GET /denied' /var/log/h3-origin.log || true); set +e; runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus sandbox-proxy-bash -c 'curl --http3-only --cacert /run/agent-sandbox/proxy-ca-bundle.pem --silent --show-error --max-time 15 https://h3-denied.test:443/denied' >/tmp/h3-denied.log 2>&1; status=$?; set -e; cat /tmp/h3-denied.log; after=$(grep -F -c 'request GET /denied' /var/log/h3-origin.log || true); test $status -eq 0; grep -F -q 'blocked by agent-sandbox policy' /tmp/h3-denied.log; test \"$before\" = \"$after\"")


      # DoH: the proxy rewrites the advertised ECH configuration with its
      # own, and rejects DNSSEC-bearing responses instead of rewriting them.
      ech_config = proxy.succeed("base64 -w0 /var/lib/agent-sandbox/proxy/ech-config-list").strip()
      sandbox_shell(
          proxy,
          "sandbox-proxy-bash",
          "curl --silent --show-error --fail --max-time 15 -X POST -H 'Content-Type: application/dns-message' --data-binary \"\" -o /tmp/doh-ech.bin http://169.254.100.1:8008/doh-ech && python3 -c 'import base64,sys; expected=base64.b64decode(\"%s\"); data=open(\"/tmp/doh-ech.bin\",\"rb\").read(); sys.exit(0 if expected in data else 1)'" % ech_config,
          wrapper=session_wrapper,
      )
      sandbox_shell(
          proxy,
          "sandbox-proxy-bash",
          "status=$(curl --silent --show-error --max-time 15 --write-out '%{http_code}' --output /tmp/doh-dnssec.bin -X POST -H 'Content-Type: application/dns-message' --data-binary \"\" http://169.254.100.1:8008/doh-dnssec); test \"$status\" = 403 && grep -F -q 'blocked by agent-sandbox policy' /tmp/doh-dnssec.bin",
          wrapper=session_wrapper,
      )

      # TLS identity: the SNI must match the origin certificate. The policy
      # target is allowed, but the certificate carries only IP SANs, so the
      # upstream handshake must fail closed.
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "https://allowed.test:8443/allowed", wrapper=session_wrapper, expect_success=False)
      sandbox_shell(
          proxy,
          "sandbox-proxy-bash",
          "curl --silent --show-error --max-time 15 -o /dev/null -w '%{http_code}' https://allowed.test:8443/allowed | grep -q 502",
          wrapper=session_wrapper,
      )

      # Sudo deny is an immediate guard failure; approve mode executes the
      # declaratively allowed command with arguments but rejects sudo options.
      sandbox_shell(sudo_deny, "sandbox-sudo-deny-bash", 'sudo id 2>&1 | grep -q "sudo is disabled"')
      sudo_approve.wait_for_unit("agent-sandbox-vm-policy.service")
      sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", 'sudo id | grep -q "uid=0(root)"')
      sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "sudo sh -c id", expect_success=False)
      sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "test \"$(sudo id -u)\" = 0")
      sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "sudo -u nobody id", expect_success=False)

      # Runtime approval flow: an unapproved URL pends, the per-package
      # approval persists a package-scoped rule, other packages stay
      # isolated, and a once-scoped deny resolves only its own request.
      approval.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
      approval.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
      approval.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
      approval.wait_for_unit("agent-sandbox-policy.service")
      approval.wait_for_open_port(8008)
      approval.succeed(
          "test \"$(runuser -u sandbox -- agent-sandbox-approve pending)\" = 'No pending approvals.'"
      )

      approve_env = ["env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"]
      pending_http_id = "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"http\" {print $1; exit}'"

      def package_cmd(package, script, *, background=False):
          # The wrapper records $PWD as the project root, so the sandboxed
          # command runs from the sandbox user's home for the package rule
          # to land in a predictable project file.
          inner = f"cd /home/user && {shlex.join([package, '-c', script])}"
          if background:
              # Fully detach stdio so the test driver's shell prompt returns
              # immediately instead of waiting on the sandbox's inherited fds.
              detached = (
                  "nohup runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 "
                  "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
                  f"sh -c {shlex.quote(inner)} </dev/null >/tmp/approve-bg.out 2>&1 &"
              )
              return command("sh", "-c", detached)
          return command("runuser", "-u", "sandbox", "--", *approve_env, "sh", "-c", inner)

      # The first request from the package pends; approving it at
      # project_package scope lets the held connection complete.
      approval.succeed(
          package_cmd("sandbox-approve-bash", "curl --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed", background=True)
      )
      approval.wait_until_succeeds(
          "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/allowed'"
      )
      allowed_id = approval.succeed(pending_http_id).strip()
      assert "http:" in allowed_id, allowed_id
      approval.succeed(
          f"runuser -u sandbox -- agent-sandbox-approve approve {allowed_id} project_package"
      )
      approval.wait_until_succeeds("grep -q allowed-get /tmp/approve-bg.out")

      # The rule persists to the package-specific project file and applies
      # to later requests from the same package without a prompt.
      approval.succeed("test -f /home/user/.agent-sandbox/packages/sandbox-approve-bash.json")
      approval.succeed(
          "grep -F -q 'http://169.254.100.1:8008/allowed' /home/user/.agent-sandbox/packages/sandbox-approve-bash.json"
      )
      approval.succeed(
          package_cmd("sandbox-approve-bash", "curl --fail --silent --show-error --max-time 15 http://169.254.100.1:8008/allowed | grep -q allowed-get")
      )
      approval.succeed(
          "runuser -u sandbox -- agent-sandbox-approve pending | grep -v -F 'http://169.254.100.1:8008/allowed'"
      )

      # Another package is not covered by the rule: its request to the same
      # approved URL pends separately, and a once-scoped deny blocks only
      # that request without persisting.
      approval.succeed(
          package_cmd("sandbox-approve-other-bash", "curl --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed", background=True)
      )
      approval.wait_until_succeeds(
          "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/allowed'"
      )
      other_id = approval.succeed(pending_http_id).strip()
      approval.succeed(f"runuser -u sandbox -- agent-sandbox-approve deny {other_id} once")
      approval.wait_until_succeeds("grep -F -q 'blocked by agent-sandbox policy' /tmp/approve-bg.out")

      # The once deny did not persist: the same request pends again.
      approval.succeed(
          package_cmd("sandbox-approve-other-bash", "curl --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed", background=True)
      )
      approval.wait_until_succeeds(
          "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q 'http://169.254.100.1:8008/allowed'"
      )

      # Resource pending attribution: an unlisted socket connect pends with
      # the package attributed, and a project_package approval persists the
      # rule to the package-specific project file.
      resource_approval.wait_for_unit("agent-sandbox-vm-resource-pending-server.service")
      resource_approval.succeed("test -S /run/agent-sandbox-test/pending.sock")

      def resource_bg(script):
          inner = f"cd /home/user && {shlex.join(['sandbox-resource-approve-bash', '-c', script])}"
          detached = (
              "nohup runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 "
              f"sh -c {shlex.quote(inner)} </dev/null >/tmp/resource-pending.out 2>&1 &"
          )
          return command("sh", "-c", detached)

      resource_approval.succeed(
          resource_bg("printf pending-ok | socat -T 30 - UNIX-CONNECT:/run/agent-sandbox-test/pending.sock")
      )
      resource_approval.wait_until_succeeds(
          "runuser -u sandbox -- agent-sandbox-approve pending | grep -F -q '/run/agent-sandbox-test/pending.sock'"
      )
      # The pending carries the package attribution.
      resource_approval.succeed(
          "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"resource\" {print $5}' | grep -q 'sandbox-resource-approve-bash'"
      )
      pending_res_id = resource_approval.succeed(
          "runuser -u sandbox -- agent-sandbox-approve pending | awk -F'\\t' '$2 == \"resource\" {print $1; exit}'"
      ).strip()
      resource_approval.succeed(
          f"runuser -u sandbox -- agent-sandbox-approve approve {pending_res_id} project_package"
      )
      resource_approval.wait_until_succeeds("grep -q pending-ok /tmp/resource-pending.out")
      resource_approval.succeed(
          "test -f /home/user/.agent-sandbox/packages/sandbox-resource-approve-bash.json"
      )
    '';
  });
  wrappingPackages = [
    (mkBash "sandbox-wrapping-bash" {
      extraPkgs = commonExtraPkgs;
    })
  ];
in
vmTest
