{
  pkgs,
  inputs,
  lib,
  ...
}:
let
  module = ../../modules/nixos/agent-sandbox;

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
        exec ${lib.getExe pkgs.curl} "$@"
      '';
      binary = name;
    };

  commonExtraPkgs = with pkgs; [
    coreutils
    dbus
    socat
    sudo
    util-linux
  ];
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
        subjectAltName=IP:169.254.100.1
        EOF
        openssl x509 -req -sha256 -days 3650 \
          -in "$out/server.csr" \
          -CA "$out/ca-cert.pem" -CAkey "$out/ca-key.pem" -CAcreateserial \
          -extfile server.ext -out "$out/server-cert.pem" >/dev/null 2>&1
        rm "$out/server.csr" "$out/ca-cert.srl"
      '';

  staticPackages = [
    (mkBash "sandbox-static-bash" {
      extraPkgs = commonExtraPkgs;
      readonlyDirs = [ "/var/lib/agent-sandbox-test/readonly-dir" ];
      readwriteDirs = [ "~/sandbox-readwrite" ];
      readonlyFiles = [
        "/var/lib/agent-sandbox-test/readonly-file"
        "~/sandbox-home-readonly"
      ];
      readwriteFiles = [ "/var/lib/agent-sandbox-test/readwrite-file" ];
      devicePaths = [ "/dev/agent-sandbox-test-device" ];
      exposeWorkingDirectory = true;
    })
    (mkBash "sandbox-static-options-bash" {
      extraPkgs = commonExtraPkgs;
      runtimeReadonlyDirs = [ "/run/agent-sandbox-test-runtime" ];
      blockEnvVars = [ "CUSTOM_SECRET" ];
      extraBwrapArgs = [
        "--setenv"
        "AGENT_SANDBOX_EXTRA_BWRAP"
        "covered"
      ];
    })
    (mkBash "sandbox-static-no-cwd-bash" {
      extraPkgs = commonExtraPkgs;
      runtimeReadonlyDirs = [ ];
      exposeWorkingDirectory = false;
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
  wrappingPackages = [
    (mkBash "sandbox-wrapping-bash" {
      extraPkgs = commonExtraPkgs;
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

  resourcePackages = [
    (mkBash "sandbox-resource-bash" {
      extraPkgs = commonExtraPkgs;
    })
  ];

  directNetworkPackages = [
    (mkCurl "sandbox-direct-curl" {
      extraPkgs = commonExtraPkgs;
    })
    (mkBash "sandbox-direct-bash" {
      extraPkgs = commonExtraPkgs ++ [ pkgs.curl ];
    })
  ];

  proxyNetworkPackages = [
    (mkCurl "sandbox-proxy-curl" {
      extraPkgs = commonExtraPkgs;
    })
    (mkBash "sandbox-proxy-bash" {
      extraPkgs = commonExtraPkgs ++ [ pkgs.curl ];
    })
  ];

  sudoDenyPackages = [
    (mkBash "sandbox-sudo-deny-bash" {
      extraPkgs = commonExtraPkgs;
    })
  ];

  sudoApprovePackages = [
    (mkBash "sandbox-sudo-approve-bash" {
      extraPkgs = commonExtraPkgs;
      readonlyDirs = [ "~/.config/agent-sandbox" ];
    })
  ];

  emptyPolicySection = ''{ "allow": [], "deny": [] }'';

  mkPolicy =
    name:
    {
      sudo ? emptyPolicySection,
      filesystem ? emptyPolicySection,
      resources ? emptyPolicySection,
      dbus ? emptyPolicySection,
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

  dbusPolicy = mkPolicy "dbus" {
    resources = ''
      {
        "allow": [
          { "kind": "unix_socket", "path": "/var/lib/agent-sandbox-test/dbus-runtime", "access": "connect" },
          { "kind": "unix_socket", "path": "/var/lib/agent-sandbox-test/dbus-runtime", "access": "send" }
        ],
        "deny": []
      }
    '';
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
  };

  sudoPolicy = mkPolicy "sudo" {
    sudo = ''
      {
        "allow": [ { "argv": [ "id" ], "comment": "VM elevation contract" } ],
        "deny": []
      }
    '';
  };

  testUser = {
    isNormalUser = true;
    uid = 1000;
    home = "/home/user";
    group = "users";
    extraGroups = [ "dialout" ];
    linger = true;
  };

  baseNode = {
    boot.kernelParams = [ "audit=0" ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    networking.firewall.enable = false;
    nixpkgs.overlays = lib.mkForce [ ];
    users.users.sandbox = testUser;
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
    ];
    environment.etc."agent-sandbox-test/hidden-file".text = "hidden file marker\n";
  };

  installPolicy = policy: {
    environment.etc."agent-sandbox-vm-policy.json".source = policy;
    systemd.services.agent-sandbox-vm-policy = {
      wantedBy = [ "multi-user.target" ];
      before = [ "agent-sandbox-policy.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        install -d -o sandbox -g users /home/user/.config/agent-sandbox
        install -o sandbox -g users ${policy} /home/user/.config/agent-sandbox/policy.json
      '';
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
            if path not in bodies:
                self.send_error(404)
                return
            self.respond(bodies[path])

        def do_POST(self):
            self.respond(b"post-ok\n")

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
        wantedBy = [ "multi-user.target" ];
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
          User = "sandbox";
          Restart = "on-failure";
        };
      };
    };

  httpServers = specs: {
    systemd.services = lib.listToAttrs (map httpServer specs);
  };

  vmTest = pkgs.testers.runNixOSTest (_: {
    name = "agent-sandbox-e2e";
    node.specialArgs = { inherit inputs; };

    nodes = {
      static =
        _:
        baseNode
        // {
          imports = [ module ];
          agent-sandbox = {
            enable = true;
            packages = staticPackages;
            sudoPolicy = "deny";
            wrapping.unsafeAliasPrefix = "unwrapped-";
            readonlyDirs = [ "/var/lib/agent-sandbox-test/global-readonly-dir" ];
            readwriteDirs = [ "/var/lib/agent-sandbox-test/global-readwrite-dir" ];
            readonlyFiles = [ "/var/lib/agent-sandbox-test/global-readonly-file" ];
            readwriteFiles = [ "/var/lib/agent-sandbox-test/global-readwrite-file" ];
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

      dynamic =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (installPolicy dynamicPolicy) {
            imports = [ module ];
            agent-sandbox = {
              enable = true;
              packages = dynamicPackages;
              policy = {
                interactiveApproval = false;
                uiBackend = "none";
                exportedNix = "/var/lib/agent-sandbox/exported-policy.nix";
              };
              gates.filesystem.enable = true;
            };
          }
        );

      resource =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (installPolicy resourcePolicy) {
            imports = [ module ];
            services.dbus.enable = true;
            agent-sandbox = {
              enable = true;
              packages = resourcePackages;
              policy = {
                interactiveApproval = false;
                uiBackend = "none";
                dbus.enable = false;
              };
              gates.filesystem.enable = true;
              gates.resources.enable = true;
            };
            systemd.services.agent-sandbox-vm-resource-server = {
              wantedBy = [ "multi-user.target" ];
              after = [ "agent-sandbox-vm-policy.service" ];
              serviceConfig = {
                ExecStart = "${pkgs.socat}/bin/socat UNIX-LISTEN:/run/agent-sandbox-test/echo.sock,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
                User = "sandbox";
                RuntimeDirectory = "agent-sandbox-test";
                Restart = "on-failure";
              };
            };
            systemd.services.agent-sandbox-vm-resource-denied-server = {
              wantedBy = [ "multi-user.target" ];
              requires = [ "agent-sandbox-vm-resource-server.service" ];
              after = [ "agent-sandbox-vm-resource-server.service" ];
              serviceConfig = {
                ExecStart = "${pkgs.socat}/bin/socat UNIX-LISTEN:/run/agent-sandbox-test/denied.sock,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
                User = "sandbox";
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
            services.dbus.enable = true;
            agent-sandbox = {
              enable = true;
              packages = [
                (mkBash "sandbox-dbus-bash" {
                  extraPkgs = commonExtraPkgs;
                })
              ];
              policy = {
                interactiveApproval = false;
                uiBackend = "none";
                dbus = {
                  enable = true;
                  socketDirectory = "/var/lib/agent-sandbox-test/dbus-runtime";
                  upstreamAddress = "unix:path=/run/user/1000/bus";
                  declarativeAllow = [
                    {
                      target = {
                        bus = "session";
                        destination = "org.freedesktop.DBus";
                        objectPath = "/org/freedesktop/DBus";
                        interface = "org.freedesktop.DBus";
                        member = "ListNames";
                        messageKind = "method_call";
                        signature = "";
                      };
                      comment = "VM module serialization allow";
                    }
                  ];
                  declarativeDeny = [
                    {
                      target = {
                        bus = "session";
                        destination = "org.freedesktop.DBus";
                        objectPath = "/org/freedesktop/DBus";
                        interface = "org.freedesktop.DBus";
                        member = "GetId";
                        messageKind = "method_call";
                        signature = "";
                      };
                      comment = "VM module serialization deny";
                    }
                  ];
                };
              };
              gates.filesystem.enable = true;
              gates.resources.enable = true;
            };
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
              systemd.services = {
                agent-sandbox-vm-udp-18082 = {
                  wantedBy = [ "multi-user.target" ];
                  serviceConfig = {
                    ExecStart = "${pkgs.socat}/bin/socat UDP4-RECVFROM:18082,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
                    User = "sandbox";
                    Restart = "on-failure";
                  };
                };
                agent-sandbox-vm-udp-18083 = {
                  wantedBy = [ "multi-user.target" ];
                  serviceConfig = {
                    ExecStart = "${pkgs.socat}/bin/socat UDP4-RECVFROM:18083,fork,reuseaddr EXEC:${pkgs.coreutils}/bin/cat";
                    User = "sandbox";
                    Restart = "on-failure";
                  };
                };
                agent-sandbox-vm-dns = {
                  wantedBy = [ "multi-user.target" ];
                  requires = [ "agent-sandbox-netns.service" ];
                  after = [ "agent-sandbox-netns.service" ];
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
              };
              imports = [ module ];
              agent-sandbox = {
                enable = true;
                packages = directNetworkPackages;
                policy = {
                  interactiveApproval = false;
                  uiBackend = "none";
                };
                gates.syscalls.enable = true;
                network = {
                  enable = true;
                  dnsForwardTarget = "169.254.100.1:5353";
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
                };
              };
            }
        );

      proxy =
        _:
        baseNode
        // (httpServers [
          { port = 8008; }
          {
            port = 8443;
            serviceName = "https";
            certificate = "${tlsFixture}/server-cert.pem";
            privateKey = "${tlsFixture}/server-key.pem";
          }
        ])
        // {
          imports = [ module ];
          agent-sandbox = {
            enable = true;
            packages = proxyNetworkPackages;
            policy = {
              interactiveApproval = false;
              uiBackend = "none";
            };
            gates.syscalls.enable = true;
            network = {
              enable = true;
              vethHost = "asbx-test-host";
              vethNetns = "asbx-test-ns";
              httpProxy = {
                enable = true;
                caCertificateFile = "${tlsFixture}/ca-cert.pem";
                caPrivateKeyFile = "${tlsFixture}/ca-key.pem";
                upstreamAllowCidrs = [ "169.254.100.1/32" ];
                declarativeAllow = [
                  {
                    url = "http://169.254.100.1:8008/allowed";
                    methods = [ "GET" ];
                  }
                  {
                    url = "http://169.254.100.1:8008/stream";
                    methods = [ "GET" ];
                  }
                  {
                    url = "https://169.254.100.1:8443/allowed";
                    methods = [ "GET" ];
                  }
                ];
                declarativeDeny = [
                  {
                    url = "http://169.254.100.1:8008/denied";
                    allMethods = true;
                  }
                  {
                    url = "https://169.254.100.1:8443/denied";
                    allMethods = true;
                  }
                ];
              };
            };
          };
        };

      "sudo-deny" =
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

      "sudo-approve" =
        _:
        lib.recursiveUpdate baseNode (
          lib.recursiveUpdate (installPolicy sudoPolicy) {
            imports = [ module ];
            agent-sandbox = {
              enable = true;
              packages = sudoApprovePackages;
              sudoPolicy = "approve";
              policy = {
                interactiveApproval = false;
                uiBackend = "none";
              };
            };
          }
        );
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

      for node in [static, wrapping, dynamic, resource, dbus, direct, proxy, sudo_deny, sudo_approve]:
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

      # Transparent HTTP(S) policy: allowed URLs and methods reach local
      # plaintext and TLS servers, while denied URLs are killed by the proxy.
      proxy.wait_for_unit("agent-sandbox-proxy.service", timeout=120)
      proxy.wait_for_unit("agent-sandbox-proxy-route.service", timeout=120)
      proxy.wait_for_unit("agent-sandbox-nfq.service", timeout=120)
      proxy.wait_for_unit("user@1000.service")
      proxy.wait_for_open_port(8008)
      proxy.wait_for_open_port(8443)
      proxy.succeed("curl --fail --silent -X POST http://127.0.0.1:8008/allowed | grep -q post-ok")
      proxy.succeed("curl --fail --silent http://127.0.0.1:8008/unlisted | grep -q unlisted-get")
      proxy.succeed("curl --fail --silent --cacert ${tlsFixture}/ca-cert.pem https://169.254.100.1:8443/allowed | grep -q allowed-get")
      sandbox_shell(proxy, "sandbox-proxy-bash", "test \"$SSL_CERT_FILE\" = /run/agent-sandbox/mitmproxy-ca-bundle.pem && test \"$NODE_EXTRA_CA_CERTS\" = /run/agent-sandbox/mitmproxy-ca-bundle.pem && test -r \"$SSL_CERT_FILE\"", wrapper=session_wrapper)
      sandbox_shell(proxy, "sandbox-proxy-bash", "curl --fail --silent --show-error --max-time 30 http://169.254.100.1:8008/allowed | grep -q allowed-get", wrapper=session_wrapper)
      sandbox_shell(proxy, "sandbox-proxy-bash", "curl --fail --silent --show-error --max-time 30 https://169.254.100.1:8443/allowed | grep -q allowed-get", wrapper=session_wrapper)
      sandbox_shell(proxy, "sandbox-proxy-bash", "timeout 3 curl --no-buffer --fail --silent --show-error 'http://169.254.100.1:8008/stream?alt=sse' | grep -q 'data: first'", wrapper=session_wrapper)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "http://169.254.100.1:8008/denied", wrapper=session_wrapper, expect_success=False)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "-X", "POST", "http://169.254.100.1:8008/denied", wrapper=session_wrapper, expect_success=False)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "-X", "POST", "http://169.254.100.1:8008/allowed", wrapper=session_wrapper, expect_success=False)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "http://169.254.100.1:8008/unlisted", wrapper=session_wrapper, expect_success=False)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "https://169.254.100.1:8443/denied", wrapper=session_wrapper, expect_success=False)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "-X", "POST", "https://169.254.100.1:8443/allowed", wrapper=session_wrapper, expect_success=False)
      sandbox_exec(proxy, "sandbox-proxy-curl", "--fail", "--silent", "--show-error", "--max-time", "15", "https://169.254.100.1:8443/unlisted", wrapper=session_wrapper, expect_success=False)

      # Sudo deny is an immediate guard failure; approve mode executes the
      # declaratively allowed command with arguments but rejects sudo options.
      sandbox_shell(sudo_deny, "sandbox-sudo-deny-bash", 'sudo id 2>&1 | grep -q "sudo is disabled"')
      sudo_approve.wait_for_unit("agent-sandbox-vm-policy.service")
      sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", 'sudo id | grep -q "uid=0(root)"')
      sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "sudo sh -c id", expect_success=False)
      sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "test \"$(sudo id -u)\" = 0")
      sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "sudo -u nobody id", expect_success=False)
    '';
  });
in
vmTest
