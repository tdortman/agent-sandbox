{
  config,
  lib,
  pkgs,
  inputs,
  ...
}:
let
  agentSandboxLib = import ./lib.nix {
    inherit lib;
    inherit (flake) jail-nix;
  };
  cfg = config.agent-sandbox;
  cidrValid = value: builtins.match "^.+/.+$" value != null;
  credentialPathValid =
    path:
    path == null || (lib.hasPrefix "/" path && !(lib.hasInfix "\n" path) && !(lib.hasInfix "\r" path));
  dbusFdMetadataType = lib.types.submodule {
    options = {
      kind = lib.mkOption {
        type = lib.types.str;
        default = "unknown";
      };

      readOnly = lib.mkOption {
        type = lib.types.bool;
        default = false;
      };
    };
  };
  dbusRuleJson =
    rule:
    {
      target = {
        inherit (rule.target)
          bus
          destination
          interface
          member
          signature
          ;

        fd_metadata = map (fd: {
          inherit (fd) kind;
          read_only = fd.readOnly;
        }) rule.target.fdMetadata;

        message_kind = rule.target.messageKind;
        object_path = rule.target.objectPath;
      };
    }
    // lib.optionalAttrs (rule.comment != null) {
      inherit (rule) comment;
    };
  dbusRuleType = lib.types.submodule {
    options = {
      comment = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
      };

      target = lib.mkOption { type = dbusTargetType; };
    };
  };
  dbusTargetType = lib.types.submodule {
    options = {
      bus = lib.mkOption {
        type = lib.types.enum [
          "session"
          "system"
        ];

        default = "session";
      };

      destination = lib.mkOption { type = lib.types.str; };

      fdMetadata = lib.mkOption {
        type = lib.types.listOf dbusFdMetadataType;
        default = [ ];
      };

      interface = lib.mkOption { type = lib.types.str; };
      member = lib.mkOption { type = lib.types.str; };

      messageKind = lib.mkOption {
        type = lib.types.enum [
          "method_call"
          "method_return"
          "error"
          "signal"
        ];

        default = "method_call";
      };

      objectPath = lib.mkOption { type = lib.types.str; };
      signature = lib.mkOption { type = lib.types.str; };
    };
  };
  filesystemAccessType = lib.types.enum [
    "read"
    "write"
    "read_write"
    "execute"
    "all"
  ];
  filesystemRuleType = lib.types.submodule {
    options = {
      access = lib.mkOption {
        type = filesystemAccessType;
        default = "all";
        description = "Access mode covered by this rule.";
      };

      path = lib.mkOption {
        type = policyPathType;
        description = "Filesystem path matched by this rule. ${policyPathDescription}";
      };
    };
  };
  flake = import ../../../lib/consumer.nix { inherit inputs pkgs; };
  # The Rust workspace package installs agent-sandbox-fs-arm and agent-sandbox-fsmon.
  fsArmPkg = policyPkg;
  hiddenPathDescription = ''
    Paths masked inside dynamic-FS sandboxes (``gates.filesystem.enable``).
    The wrapper bind-mounts the host root, then overlays these entries so
    the sandbox cannot see their contents: directories become empty tmpfs
    mounts, files become ``/dev/null``. Use ``~/…`` for paths under the
    invoking user's ``$HOME``, or ``/…`` for absolute host paths.
  '';
  hiddenPathType = mountPathType;
  http10OriginType = lib.types.addCheck httpUrlType (
    origin:
    let
      match = builtins.match "^https?://([[][0-9A-Fa-f:.]+[]]|[^/:@#[:space:]]+)(:[0-9]{1,5})?(/[^#[:space:]]*)?$" origin;
      path = if match == null then null else builtins.elemAt match 2;
    in
    lib.assertMsg (builtins.match ".*[*?].*" origin == null && (path == null || path == "/"))
      "agent-sandbox HTTP/1.0 upstream origins must be exact HTTP(S) origins without globs or paths, got: ${origin}"
  );
  httpMethodType = lib.types.addCheck lib.types.str (
    method:
    lib.assertMsg (
      builtins.stringLength method <= 64 && builtins.match "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$" method != null
    ) "agent-sandbox HTTP rule methods must contain valid HTTP method tokens, got: ${method}"
  );
  httpRuleJson =
    rule:
    assert lib.assertMsg
      (
        (rule.methods != null && builtins.length rule.methods > 0 && !rule.allMethods)
        || (rule.allMethods && (rule.methods == null || builtins.length rule.methods == 0))
      )
      "agent-sandbox HTTP rule at ${rule.url} must set exactly one of a non-empty methods list or allMethods = true (allMethods cannot be combined with methods)";
    {
      inherit (rule) url;
      methods = if rule.allMethods then [ ] else rule.methods;
    }
    // lib.optionalAttrs (rule.comment != null) {
      inherit (rule) comment;
    };
  httpRuleType = lib.types.submodule {
    options = {
      allMethods = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Match every HTTP method at this URL.";
      };

      comment = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Optional operator comment for this rule.";
      };

      methods = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf httpMethodType);
        default = null;
        description = "HTTP method token list to match; empty means all methods only with allMethods = true.";
      };

      url = lib.mkOption {
        type = httpUrlType;
        description = "Absolute HTTP(S) URL to match.";
      };
    };
  };
  httpRules = {
    type = lib.types.listOf httpRuleType;
    default = [ ];
  };
  httpUrlType = lib.types.addCheck lib.types.str (
    url:
    let
      match = builtins.match "^https?://([[][0-9A-Fa-f:.]+[]]|[^/:@#[:space:]]+)(:[0-9]{1,5})?(/[^#[:space:]]*)?$" url;
      normalizedPort =
        if portDigits == null then
          null
        else
          let
            normalized = builtins.match "0*([1-9][0-9]*|0)" portDigits;
          in
          if normalized == null then null else builtins.elemAt normalized 0;
      port = if match == null then null else builtins.elemAt match 1;
      portDigits =
        if port == null then null else builtins.substring 1 (builtins.stringLength port - 1) port;
      portValue =
        if normalizedPort == null then null else builtins.tryEval (builtins.fromJSON normalizedPort);
    in
    lib.assertMsg
      (
        match != null
        && (port == null || (portValue.success && portValue.value >= 1 && portValue.value <= 65535))
      )
      "agent-sandbox HTTP rule url must be an absolute HTTP(S) URL with valid glob syntax and no fragment, got: ${url}"
  );
  isValidMountPath = path: path == "~" || lib.hasPrefix "~/" path || lib.hasPrefix "/" path;
  mergePackageMounts =
    pkgCfg:
    pkgCfg
    // {
      hiddenPaths = lib.unique (cfg.hiddenPaths ++ pkgCfg.hiddenPaths);
      readonlyDirs = lib.unique (cfg.readonlyDirs ++ sharedRuntimeReadonly ++ pkgCfg.readonlyDirs);
      readonlyFiles = lib.unique (cfg.readonlyFiles ++ pkgCfg.readonlyFiles);
      readwriteDirs = lib.unique (cfg.readwriteDirs ++ pkgCfg.readwriteDirs);
      readwriteFiles = lib.unique (cfg.readwriteFiles ++ pkgCfg.readwriteFiles);
    };
  mountOptions = {
    readonlyDirs = lib.mkOption {
      type = lib.types.listOf mountPathType;
      default = [ ];
      description = "Directories mounted read-only. ${mountPathDescription}";
    };

    readonlyFiles = lib.mkOption {
      type = lib.types.listOf mountPathType;
      default = [ ];
      description = "Files mounted read-only. ${mountPathDescription}";
    };

    readwriteDirs = lib.mkOption {
      type = lib.types.listOf mountPathType;
      default = [ ];
      description = "Directories mounted read-write. ${mountPathDescription}";
    };

    readwriteFiles = lib.mkOption {
      type = lib.types.listOf mountPathType;
      default = [ ];
      description = "Files mounted read-write. ${mountPathDescription}";
    };
  };
  mountPathDescription = ''
    Each entry must be an absolute path: `~/…` under the invoking user's `$HOME`
    (for example `"~/.agents"`), or `/…` on the host (for example `"/run/user/1000"`).
  '';
  mountPathType = lib.types.addCheck lib.types.str (
    path:
    lib.assertMsg (isValidMountPath path) ''
      agent-sandbox mount path must start with ~/ or / (for example "~/.agents" or "/run/user/1000"), got: ${path}
    ''
  );
  packageEffectiveName =
    value:
    if value.name != null then
      value.name
    else if value.binary != null then
      value.binary
    else
      value.package.pname or (lib.getName value.package);
  packageHasPolicy =
    value:
    value.policy.network.direct.allow != [ ]
    || value.policy.network.direct.deny != [ ]
    || value.policy.network.http.allow != [ ]
    || value.policy.network.http.deny != [ ]
    || value.policy.filesystem.allow != [ ]
    || value.policy.filesystem.deny != [ ]
    || value.policy.resources.allow != [ ]
    || value.policy.resources.deny != [ ]
    || value.policy.dbus.allow != [ ]
    || value.policy.dbus.deny != [ ]
    || value.policy.sudo.allow != [ ]
    || value.policy.sudo.deny != [ ];
  packageNameValid = name: name != "" && !(lib.hasInfix "/" name) && !(lib.hasInfix ".." name);
  packageOptions = mountOptions // {
    package = lib.mkOption {
      type = lib.types.package;
      description = "The package to wrap.";
    };

    binary = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Override the main executable name; when null, uses lib.baseNameOf (lib.getExe package).";
    };

    blockEnvVars = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = agentSandboxLib.defaultBlockEnvVars;
    };

    devicePaths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = agentSandboxLib.defaultDevicePaths;

      description = ''
        Extra device nodes to bind into the jail (rw). Standard NVIDIA devices
        (including nvidia-fs when enabled) are bound automatically.
      '';
    };

    exposeWorkingDirectory = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };

    extraBwrapArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
    };

    extraPkgs = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
    };

    hiddenPaths = lib.mkOption {
      type = lib.types.listOf hiddenPathType;
      default = [ ];

      description = ''
        ${hiddenPathDescription}
        Merged with ``agent-sandbox.hiddenPaths`` for this package only.
      '';
    };

    name = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Package name used for sandbox session attribution and per-package policy files; when null, uses the wrapped binary name.";
    };

    policy = lib.mkOption {
      type = lib.types.submodule {
        options = {
          dbus = {
            allow = lib.mkOption {
              type = lib.types.listOf dbusRuleType;
              default = [ ];
              description = "D-Bus capabilities allowed without interactive approval for this package.";
            };

            deny = lib.mkOption {
              type = lib.types.listOf dbusRuleType;
              default = [ ];
              description = "D-Bus capabilities denied for this package even when another policy allows them.";
            };
          };

          filesystem = {
            allow = lib.mkOption {
              type = lib.types.listOf filesystemRuleType;
              default = [ ];
              description = "Filesystem rules allowed without interactive approval for this package.";
            };

            deny = lib.mkOption {
              type = lib.types.listOf filesystemRuleType;
              default = [ ];
              description = "Filesystem rules denied for this package even when another policy allows them.";
            };
          };

          network = {
            direct = {
              allow = lib.mkOption {
                type = lib.types.listOf ruleType;
                default = [ ];
                description = "Hosts allowed without interactive approval for this package.";
              };

              deny = lib.mkOption {
                type = lib.types.listOf ruleType;
                default = [ ];
                description = "Hosts denied for this package even when another policy allows them.";
              };
            };

            http = {
              allow = lib.mkOption {
                inherit (httpRules) type;
                default = [ ];
                description = "HTTP(S) URL rules allowed without interactive approval for this package.";
              };

              deny = lib.mkOption {
                inherit (httpRules) type;
                default = [ ];
                description = "HTTP(S) URL rules denied for this package even when another policy allows them.";
              };
            };
          };

          resources = {
            allow = lib.mkOption {
              type = lib.types.listOf resourceRuleType;
              default = [ ];
              description = "Resource rules allowed without interactive approval for this package.";
            };

            deny = lib.mkOption {
              type = lib.types.listOf resourceRuleType;
              default = [ ];
              description = "Resource rules denied for this package even when another policy allows them.";
            };
          };

          sudo = {
            allow = lib.mkOption {
              type = lib.types.listOf sudoRuleType;
              default = [ ];
              description = "Sudo command rules allowed without interactive approval for this package.";
            };

            deny = lib.mkOption {
              type = lib.types.listOf sudoRuleType;
              default = [ ];
              description = "Sudo command rules denied for this package even when another policy allows them.";
            };
          };
        };
      };

      default = { };
      description = "Per-package declarative policy; declaring a rule removes the approval prompt for this package only.";
    };

    runtimeReadonlyDirs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = agentSandboxLib.defaultRuntimeReadonlyDirs;
    };
  };
  packagePolicyJson =
    policy:
    {
      network = {
        direct = {
          allow = map (r: { inherit (r) host port; }) policy.network.direct.allow;
          deny = map (r: { inherit (r) host port; }) policy.network.direct.deny;
        };

        http = {
          allow = map httpRuleJson policy.network.http.allow;
          deny = map httpRuleJson policy.network.http.deny;
        };
      };

      sudo = {
        allow = map (r: { inherit (r) argv; }) policy.sudo.allow;
        deny = map (r: { inherit (r) argv; }) policy.sudo.deny;
      };
    }
    // lib.optionalAttrs (policy.filesystem.allow != [ ] || policy.filesystem.deny != [ ]) {
      filesystem = {
        allow = map (r: { inherit (r) access path; }) policy.filesystem.allow;
        deny = map (r: { inherit (r) access path; }) policy.filesystem.deny;
      };
    }
    // lib.optionalAttrs (policy.resources.allow != [ ] || policy.resources.deny != [ ]) {
      resources = {
        allow = map (r: { inherit (r) access kind path; }) policy.resources.allow;
        deny = map (r: { inherit (r) access kind path; }) policy.resources.deny;
      };
    }
    // lib.optionalAttrs (policy.dbus.allow != [ ] || policy.dbus.deny != [ ]) {
      dbus = {
        allow = map dbusRuleJson policy.dbus.allow;
        deny = map dbusRuleJson policy.dbus.deny;
      };
    };
  policyContextEnabled =
    cfg.network.enable
    || cfg.gates.filesystem.enable
    || cfg.sudoPolicy == "approve"
    || lib.any packageHasPolicy cfg.packages;
  policyPathDescription = ''
    Each path must start with ~/ under the invoking user's $HOME (for example
    "~/.agents"), /… on the host (for example "/run/user/1000"), or ./ for
    project-relative paths.
  '';
  policyPathType = lib.types.addCheck lib.types.str (
    path:
    lib.assertMsg (isValidMountPath path || lib.hasPrefix "./" path) ''
      agent-sandbox policy rule path must start with ~/ or / (for example "~/.agents" or "/run/user/1000"), or ./ for project-relative paths, got: ${path}
    ''
  );
  policyPkg = flake.package "agent-sandbox";
  resourceAccessType = lib.types.enum [
    "connect"
    "send"
    "all"
    "open_read"
    "open_write"
    "open_read_write"
  ];
  resourceRuleType = lib.types.submodule {
    options = {
      access = lib.mkOption {
        type = resourceAccessType;
        description = "Access mode covered by this rule.";
      };

      kind = lib.mkOption {
        type = lib.types.enum [
          "unix_socket"
          "device"
        ];

        description = "Kind of capability-granting resource matched by this rule.";
      };

      path = lib.mkOption {
        type = policyPathType;
        description = "Path of the socket or device node matched by this rule. ${policyPathDescription}";
      };
    };
  };
  ruleType = lib.types.submodule {
    options = {
      host = lib.mkOption { type = lib.types.str; };
      port = lib.mkOption { type = lib.types.port; };
    };
  };
  runtime = agentSandboxLib.mkRuntime {
    netnsEnter = "${config.security.wrapperDir}/agent-sandbox-enter";
    rootCfg = cfg;
  };
  sharedRuntimeReadonly = lib.optional cfg.network.enable "/run/netns";
  sudoGuardPkg = import ./sudo-guard.nix {
    inherit pkgs policyPkg;
    policy = cfg.sudoPolicy;
  };
  sudoRuleType = lib.types.submodule {
    options.argv = lib.mkOption {
      type = lib.types.addCheck (lib.types.listOf lib.types.str) (
        argv:
        lib.assertMsg (builtins.length argv > 0) ''
          agent-sandbox sudo rule argv must be a non-empty command list (for example ["systemctl" "restart"]), got: ${builtins.toJSON argv}
        ''
      );

      description = "Command prefix (argv[0] and arguments) matched by this rule.";
    };
  };
  # The Rust workspace package also installs agent-sandbox-syscall-arm and
  # agent-sandbox-syscall-broker. We expose both as `syscallArmPkg` so the
  # sandbox entry chain can prepend the arm helper that installs the seccomp
  # user-notification filter; the broker is spawned by policyd (see the
  # `agent-sandbox-nfq` / `agent-sandbox-policyd` systemd units).
  syscallArmPkg = policyPkg;
  wrapOne =
    value:
    agentSandboxLib.mkWrapPackage pkgs (
      lib.removeAttrs (mergePackageMounts value) [
        "name"
        "policy"
      ]
      // {
        inherit (cfg.wrapping) replaceOriginalBinary unsafeAliasPrefix;
        inherit runtime;

        inherit (runtime)
          dbus
          network
          policySocket
          sandboxPolicySocket
          ;

        inherit policyPkg;
        dbusProxyPkg = policyPkg;
        filesystemGate = cfg.gates.filesystem.enable;
        packageName = packageEffectiveName value;
        # Register the sandbox session when this package declares policy, even
        # when no global policy gate is enabled, so its package layer applies.
        policyContext = runtime.policyContext || packageHasPolicy value;
        sudoGuard = sudoGuardPkg;
      }
      // lib.optionalAttrs cfg.gates.filesystem.enable {
        inherit fsArmPkg;
      }
      //
        lib.optionalAttrs
          (
            cfg.gates.filesystem.enable
            || (cfg.gates.syscalls.enable && cfg.network.enable)
            || cfg.gates.resources.enable
          )
          {
            inherit syscallArmPkg;
          }
      // lib.optionalAttrs cfg.gates.resources.enable {
        resourceGate = true;
      }
    );

in
{
  options.agent-sandbox = {
    enable = lib.mkEnableOption "jail.nix bubblewrap sandbox + optional network policy for AI agent CLIs";

    gates = {
      filesystem.enable = lib.mkEnableOption ''
        kernel-mediated dynamic filesystem access approval via fanotify.
        Controls filesystem access at runtime using path-based allow/deny rules.
        The first process inside each sandbox becomes agent-sandbox-fs-arm,
        Dynamic filesystem mode traps unsupported directory/device/metadata,
        timestamp, and fallocate mutations before tracee-pointer classification.
        Legacy rename/link/symlink/unlink/truncate operations remain policy-gated
        with revalidation and ``CONTINUE`` for compatibility, with a residual
        directory-entry TOCTOU risk. Use static bubblewrap mounts and predeclared
        writable directories for workloads such as package installs. Static
        bubblewrap mounts remain the structural read-only/read-write boundary.
        Disabled by default. When disabled, no fs-arm helper or fsmon process
        is used and there is no kernel-level filesystem mediation.
      '';

      resources.enable = lib.mkEnableOption ''
        seccomp-backed resource gates for all AF_UNIX sockets and
        broker-opened host device nodes under /dev in dynamic filesystem mode.
        Requires gates.filesystem.enable.
      '';

      syscalls.enable = lib.mkEnableOption ''
        kernel-mediated seccomp user-notification gate for packet-emitting syscalls.
        The arm helper installs a seccomp filter inside the sandbox, then execs its
        argv tail. The host-side broker (``agent-sandbox-syscall-broker``) consults policyd
        before allowing or denying the syscall. The user-visible benefit is that a
        short-timeout UDP client such as ``dig @1.1.1.1 +time=2`` blocks inside the
        kernel until the approval prompt is answered, instead of returning before
        the prompt renders. NFQUEUE remains in place as a backstop. Disabled by
        default. When disabled, no syscall-arm helper or broker is wired.
      '';
    };

    hiddenPaths = lib.mkOption {
      type = lib.types.listOf hiddenPathType;

      default = [
        "~/.snapshots"
        "/home/.snapshots"
      ];

      description = ''
        ${hiddenPathDescription}

        Defaults to ``~/.snapshots`` and ``/home/.snapshots`` so btrfs snapshot trees are invisible inside
        sandboxes and never hit filesystem policy checks. Set to ``[]`` to
        disable masking entirely, or extend the list with additional paths.
      '';
    };

    network = {
      enable = lib.mkEnableOption "deny-by-default network via netns + NFQUEUE policy enforcement";

      declarativeAllow = lib.mkOption {
        type = lib.types.listOf ruleType;
        default = [ ];
        description = "Hosts allowed without interactive approval (merged under user/project policy).";
      };

      declarativeDeny = lib.mkOption {
        type = lib.types.listOf ruleType;
        default = [ ];
      };

      dnsForwardTarget = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.53:53";

        description = ''
          Upstream DNS server used by agent-sandbox-dns-forwarder for raw DNS
          forwarding. Defaults to the systemd-resolved stub on the host.
        '';
      };

      hostIp = lib.mkOption {
        type = lib.types.str;
        default = "169.254.100.1";
      };

      hostIp6 = lib.mkOption {
        type = lib.types.str;
        default = "fd00:dead:beef::1";
        description = "IPv6 host-side veth address (stable ULA).";
      };

      httpProxy = {
        enable = lib.mkEnableOption "transparent HTTP interception through the trusted proxy RPC";

        caCertificateFile = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Absolute path to a supplied interception CA certificate or chain.";
        };

        caPrivateKeyFile = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Absolute path to a supplied unencrypted interception CA private key.";
        };

        declarativeAllow = lib.mkOption {
          inherit (httpRules) type;
          default = [ ];

          description = ''
            HTTP(S) URL rules allowed without interactive approval. Each rule
            must set either a non-empty ``methods`` list or ``allMethods = true``.
          '';
        };

        declarativeDeny = lib.mkOption {
          inherit (httpRules) type;
          default = [ ];
          description = "HTTP(S) URL rules denied even when another policy allows them.";
        };

        gid = lib.mkOption {
          type = lib.types.nullOr lib.types.int;
          default = null;
          description = "Optional explicit group ID allowed to connect to the trusted proxy socket; null uses the dedicated proxy group.";
        };

        http10UpstreamOrigins = lib.mkOption {
          type = lib.types.listOf http10OriginType;
          default = [ ];

          description = ''
            Exact HTTP(S) origins that may use HTTP/1.0 upstream framing.
            The proxy validates each origin before startup.
          '';
        };

        http3 = {
          enable = lib.mkEnableOption "transparent HTTP/3 interception through UDP port 443";

          altUdpPorts = lib.mkOption {
            type = lib.types.listOf lib.types.port;
            default = [ ];

            description = ''
              Additional UDP ports whose intercepted QUIC traffic terminates at
              the proxy, for validated `Alt-Svc` alternative endpoints.
            '';
          };

          udpPort = lib.mkOption {
            type = lib.types.port;
            default = 443;
            description = "UDP port whose intercepted QUIC traffic terminates at the proxy.";
          };
        };

        socketPath = lib.mkOption {
          type = lib.types.str;
          default = "/run/agent-sandbox/proxy-policy.sock";
          description = "Unix socket exposed to the trusted transparent HTTP proxy.";

        };

        upstreamAllowCidrs = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "Additional CIDRs the dedicated proxy UID may reach directly.";
        };

        websocketHttp11Urls = lib.mkOption {
          type = lib.types.listOf httpUrlType;
          default = [ ];
          description = "Absolute HTTP(S) URL glob patterns whose WebSocket upstreams must use HTTP/1.1.";
        };
      };

      netnsIp = lib.mkOption {
        type = lib.types.str;
        default = "169.254.100.2";
      };

      netnsIp6 = lib.mkOption {
        type = lib.types.str;
        default = "fd00:dead:beef::2";
        description = "IPv6 netns-side veth address (stable ULA).";
      };

      netnsIp6Prefix = lib.mkOption {
        type = lib.types.int;
        default = 64;
        description = "IPv6 prefix length for the veth link (ULA /64 for SLAAC compatibility).";
      };

      netnsName = lib.mkOption {
        type = lib.types.str;
        default = "agent-sandbox";
      };

      policyTimeout = lib.mkOption {
        type = lib.types.float;
        default = 305.0;

        description = ''
          Max seconds the NFQUEUE daemon waits for policyd per transport-layer
          connection check. Should exceed ``agent-sandbox.policy.approvalTimeout``
          so that policyd's own timeout fires first. When interactive approval
          is enabled, the NFQUEUE daemon uses at least ``approvalTimeout``.
        '';
      };

      queueNumber = lib.mkOption {
        type = lib.types.int;
        default = 0;
        description = "NFQUEUE number used by nftables and agent-sandbox-nfq.";
      };

      vethHost = lib.mkOption {
        type = lib.types.str;
        default = "asbx-host";
      };

      vethNetns = lib.mkOption {
        type = lib.types.str;
        default = "asbx-ns";
      };
    };

    packages = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule { options = packageOptions; });
      default = [ ];
      description = "Agent packages wrapped for sandboxed execution.";
    };

    policy = {
      approvalTimeout = lib.mkOption {
        type = lib.types.float;
        default = 300.0;

        description = ''
          Max seconds to wait for OMP network or elevation approval after UI is connected.
        '';
      };

      autoSpawnPolicyUi = lib.mkOption {
        type = lib.types.bool;
        default = true;

        description = ''
          When no policy UI is connected, policyd spawns ``agent-sandbox-ui`` as the
          requesting user (via runuser) so non-OMP agents still get prompts.
          Set ``uiBackend = "none"`` instead for a cleaner headless setup.
        '';
      };

      dbus = {
        enable = lib.mkEnableOption "filtered session D-Bus access for sandboxes (requires gates.resources.enable)";

        declarativeAllow = lib.mkOption {
          type = lib.types.listOf dbusRuleType;
          default = [ ];
          description = "D-Bus capabilities allowed without interactive approval.";
        };

        declarativeDeny = lib.mkOption {
          type = lib.types.listOf dbusRuleType;
          default = [ ];
          description = "D-Bus capabilities denied even when another policy allows them.";
        };

        socketDirectory = lib.mkOption {
          type = lib.types.str;
          default = "/run/user";
          description = "Host directory used for per-sandbox D-Bus relay sockets.";
        };

        upstreamAddress = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Optional D-Bus upstream address; defaults to DBUS_SESSION_BUS_ADDRESS.";
        };
      };

      exportedJson = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/agent-sandbox/exported-policy.json";
      };

      exportedNix = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Optional path to export merged policy as a .nix file beside your config repo.";
      };

      filesystem = {
        declarativeAllow = lib.mkOption {
          type = lib.types.listOf filesystemRuleType;
          default = [ ];
          description = "Filesystem rules allowed without interactive approval.";
        };

        declarativeDeny = lib.mkOption {
          type = lib.types.listOf filesystemRuleType;
          default = [ ];
          description = "Filesystem rules denied even when another policy allows them.";
        };
      };

      interactiveApproval = lib.mkOption {
        type = lib.types.bool;
        default = true;

        description = ''
          When true, unknown hosts block in policyd until the UI allows or denies
          (same flow as elevation). Host-side OMP extension, ``agent-sandbox-ui``,
          or ``agent-sandbox-approve`` may approve from the host policy socket.
        '';
      };

      resources = {
        declarativeAllow = lib.mkOption {
          type = lib.types.listOf resourceRuleType;
          default = [ ];
          description = "Resource rules allowed without interactive approval.";
        };

        declarativeDeny = lib.mkOption {
          type = lib.types.listOf resourceRuleType;
          default = [ ];
          description = "Resource rules denied even when another policy allows them.";
        };
      };

      sandboxSocketPath = lib.mkOption {
        type = lib.types.str;
        default = "/run/agent-sandbox/sandbox-policy.sock";
        description = "Sandbox-facing policyd socket. Bound over policy.socketPath inside sandboxes.";
      };

      socketPath = lib.mkOption {
        type = lib.types.str;
        default = "/run/agent-sandbox/policy.sock";
      };

      sudo = {
        declarativeAllow = lib.mkOption {
          type = lib.types.listOf sudoRuleType;
          default = [ ];
          description = "Sudo command rules allowed without interactive approval. sudoPolicy remains the master switch for elevation.";
        };

        declarativeDeny = lib.mkOption {
          type = lib.types.listOf sudoRuleType;
          default = [ ];
          description = "Sudo command rules denied even when another policy allows them. sudoPolicy remains the master switch for elevation.";
        };
      };

      uiBackend = lib.mkOption {
        type = lib.types.enum [
          "qt-dialog"
          "zenity"
          "none"
        ];

        default = "qt-dialog";

        description = ''
          Which dialog backend to use for approval prompts.
          ``qt-dialog`` uses the packaged Qt6 helper (default).
          ``zenity`` uses the GTK dialog tool.
          ``none`` disables auto-spawned prompts entirely; approve and deny
          manually with ``agent-sandbox-approve`` from a terminal.
        '';
      };
    };

    sudoPolicy = lib.mkOption {
      type = lib.types.enum [
        "deny"
        "approve"
      ];

      default = "deny";

      description = ''
        How sandboxed agents may invoke sudo. ``deny`` blocks elevation.
        ``approve`` prepends an agent-sandbox guard to the sandbox PATH so
        that plain ``sudo`` inside the agent routes through policyd, and the
        approved command runs as root on the host (not inside bubblewrap).
        Host-side ``agent-sandbox-ui`` may approve. v1: ``sudo <cmd> [args…]``
        only. ``-u`` / ``-E`` and similar flags are not supported. The
        host's ``/run/wrappers`` tree is hidden inside the sandbox.
      '';
    };

    wrapping = {
      replaceOriginalBinary = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Install the sandbox launcher as the original program name (jail.nix-style).";
      };

      unsafeAliasPrefix = lib.mkOption {
        type = lib.types.str;
        default = "unsafe-";
        description = "Prefix for the unwrapped executable when replaceOriginalBinary is true.";
      };
    };
  }
  // mountOptions;

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = policyContextEnabled -> cfg.policy.socketPath != cfg.policy.sandboxSocketPath;
        message = "agent-sandbox.policy.socketPath and sandboxSocketPath must differ when policy is enabled";
      }
      {
        assertion = !(cfg.gates.resources.enable && !cfg.gates.filesystem.enable);
        message = "agent-sandbox.gates.resources.enable requires gates.filesystem.enable";
      }
      {
        assertion = !cfg.policy.dbus.enable || cfg.gates.resources.enable;
        message = "agent-sandbox.policy.dbus.enable requires gates.resources.enable";
      }
      {
        assertion = !cfg.network.httpProxy.enable || cfg.network.enable;
        message = "agent-sandbox.network.httpProxy.enable requires network.enable";
      }
      {
        assertion =
          let
            proxy = cfg.network.httpProxy;
            rules = proxy.declarativeAllow ++ proxy.declarativeDeny;
          in
          proxy.enable || rules == [ ];

        message =
          let
            proxy = cfg.network.httpProxy;
            suffix = lib.optionalString (urls != [ ]) " (configured URLs: ${lib.concatStringsSep ", " urls})";
            urls = map (rule: rule.url) (proxy.declarativeAllow ++ proxy.declarativeDeny);
          in
          "agent-sandbox.network.httpProxy.declarativeAllow/declarativeDeny require httpProxy.enable${suffix}";
      }

      {
        assertion =
          let
            proxy = cfg.network.httpProxy;
          in
          (proxy.caCertificateFile == null) == (proxy.caPrivateKeyFile == null)
          && credentialPathValid proxy.caCertificateFile
          && credentialPathValid proxy.caPrivateKeyFile;

        message = "agent-sandbox HTTP proxy CA certificate and key must be supplied together and use absolute paths";
      }
      {
        assertion =
          let
            proxy = cfg.network.httpProxy;
          in
          lib.all cidrValid proxy.upstreamAllowCidrs;

        message = "agent-sandbox.network.httpProxy.upstreamAllowCidrs entries must be non-empty CIDR strings";
      }
      {
        assertion = cfg.network.httpProxy.gid == null || cfg.network.httpProxy.gid > 0;
        message = "agent-sandbox.network.httpProxy.gid must be nonzero when explicitly configured";
      }
      {
        assertion = !cfg.network.httpProxy.http3.enable || cfg.network.httpProxy.enable;
        message = "agent-sandbox.network.httpProxy.http3.enable requires httpProxy.enable";
      }
      {
        assertion = cfg.network.httpProxy.http3.enable || cfg.network.httpProxy.http3.altUdpPorts == [ ];
        message = "agent-sandbox.network.httpProxy.http3.altUdpPorts requires http3.enable";
      }
      {
        assertion =
          let
            invalid = lib.filter (value: !(packageNameValid (packageEffectiveName value))) cfg.packages;
          in
          invalid == [ ];

        message =
          let
            invalid = lib.filter (value: !(packageNameValid (packageEffectiveName value))) cfg.packages;
          in
          "agent-sandbox package names must be non-empty and contain neither '/' nor '..', got: ${
            lib.concatMapStringsSep ", " packageEffectiveName invalid
          }";
      }
      {
        assertion =
          let
            names = map packageEffectiveName (lib.filter packageHasPolicy cfg.packages);
          in
          lib.all (name: lib.length (builtins.filter (n: n == name) names) == 1) names;

        message =
          let
            duplicates = lib.unique (
              builtins.filter (name: lib.length (builtins.filter (n: n == name) names) > 1) names
            );
            names = map packageEffectiveName (lib.filter packageHasPolicy cfg.packages);
          in
          "agent-sandbox packages declaring policy must have unique effective names (each emits /etc/agent-sandbox/packages/<name>.json); duplicates: ${lib.concatStringsSep ", " duplicates}";
      }
    ];

    environment = {
      # One root-owned declarative policy file per package that declares
      # policy; policyd loads these via --package-declarative NAME=PATH for
      # sessions attributed to the package.
      etc = lib.listToAttrs (
        map (value: {
          name = "agent-sandbox/packages/${packageEffectiveName value}.json";
          value.text = builtins.toJSON (packagePolicyJson value.policy);
        }) (lib.filter packageHasPolicy cfg.packages)
      );

      # Propagate UI backend choice to session so manually run agent-sandbox-ui
      # picks up the configured backend without needing the service environment.
      sessionVariables.AGENT_SANDBOX_UI_BACKEND = cfg.policy.uiBackend;

      systemPackages = (map wrapOne cfg.packages) ++ [
        policyPkg
      ];
    };

    nixpkgs.overlays = lib.mkAfter [
      (final: _: {
        agentSandbox = {
          inherit (agentSandboxLib)
            defaultBlockEnvVars
            defaultCommonPkgs
            defaultDevicePaths
            defaultRuntimeReadonlyDirs
            mkWrapPackage
            ;

          inherit policyPkg;
          wrapPackage = agentSandboxLib.mkWrapPackage final;
        };
      })
    ];
  };
}
