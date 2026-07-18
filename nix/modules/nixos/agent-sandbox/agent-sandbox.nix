{
  config,
  lib,
  pkgs,
  inputs,
  ...
}:
let
  flake = import ../../../lib/consumer.nix { inherit inputs pkgs; };

  agentSandboxLib = import ./lib.nix {
    inherit lib;
    inherit (flake) jail-nix;
  };

  policyPkg = flake.package "agent-sandbox";

  # The Rust workspace package installs agent-sandbox-fs-arm and agent-sandbox-fsmon.
  fsArmPkg = policyPkg;

  # The Rust workspace package also installs agent-sandbox-syscall-arm and
  # agent-sandbox-syscall-broker. We expose both as `syscallArmPkg` so the
  # sandbox entry chain can prepend the arm helper that installs the seccomp
  # user-notification filter; the broker is spawned by policyd (see the
  # `agent-sandbox-nfq` / `agent-sandbox-policyd` systemd units).
  syscallArmPkg = policyPkg;

  isValidMountPath = path: path == "~" || lib.hasPrefix "~/" path || lib.hasPrefix "/" path;

  mountPathType = lib.types.addCheck lib.types.str (
    path:
    lib.assertMsg (isValidMountPath path) ''
      agent-sandbox mount path must start with ~/ or / (for example "~/.agents" or "/run/user/1000"), got: ${path}
    ''
  );

  mountPathDescription = ''
    Each entry must be an absolute path: `~/…` under the invoking user's `$HOME`
    (for example `"~/.agents"`), or `/…` on the host (for example `"/run/user/1000"`).
  '';

  mountOptions = {
    readonlyDirs = lib.mkOption {
      type = lib.types.listOf mountPathType;
      default = [ ];
      description = "Directories mounted read-only. ${mountPathDescription}";
    };
    readwriteDirs = lib.mkOption {
      type = lib.types.listOf mountPathType;
      default = [ ];
      description = "Directories mounted read-write. ${mountPathDescription}";
    };
    readonlyFiles = lib.mkOption {
      type = lib.types.listOf mountPathType;
      default = [ ];
      description = "Files mounted read-only. ${mountPathDescription}";
    };
    readwriteFiles = lib.mkOption {
      type = lib.types.listOf mountPathType;
      default = [ ];
      description = "Files mounted read-write. ${mountPathDescription}";
    };
  };

  hiddenPathType = mountPathType;

  hiddenPathDescription = ''
    Paths masked inside dynamic-FS sandboxes (``gates.filesystem.enable``).
    The wrapper bind-mounts the host root, then overlays these entries so
    the sandbox cannot see their contents: directories become empty tmpfs
    mounts, files become ``/dev/null``. Use ``~/…`` for paths under the
    invoking user's ``$HOME``, or ``/…`` for absolute host paths.
  '';

  httpUrlType = lib.types.addCheck lib.types.str (
    url:
    let
      match = builtins.match "^https?://([[][0-9A-Fa-f:.]+[]]|[^/:@#[:space:]]+)(:[0-9]{1,5})?(/[^#[:space:]]*)?$" url;
      port = if match == null then null else builtins.elemAt match 1;
      portDigits =
        if port == null then null else builtins.substring 1 (builtins.stringLength port - 1) port;
      normalizedPort =
        if portDigits == null then
          null
        else
          let
            normalized = builtins.match "0*([1-9][0-9]*|0)" portDigits;
          in
          if normalized == null then null else builtins.elemAt normalized 0;
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

  httpMethodType = lib.types.addCheck lib.types.str (
    method:
    lib.assertMsg (
      builtins.stringLength method <= 64 && builtins.match "^[!#$%&'*+.^_`|~0-9A-Za-z-]+$" method != null
    ) "agent-sandbox HTTP rule methods must contain valid HTTP method tokens, got: ${method}"
  );

  httpRuleType = lib.types.submodule {
    options = {
      url = lib.mkOption {
        type = httpUrlType;
        description = "Absolute HTTP(S) URL to match.";
      };
      methods = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf httpMethodType);
        default = null;
        description = "HTTP method token list to match; empty means all methods only with allMethods = true.";
      };
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
    };
  };
  httpRules = {
    type = lib.types.listOf httpRuleType;
    default = [ ];
  };
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
      objectPath = lib.mkOption { type = lib.types.str; };
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
      signature = lib.mkOption { type = lib.types.str; };
      fdMetadata = lib.mkOption {
        type = lib.types.listOf dbusFdMetadataType;
        default = [ ];
      };
    };
  };

  dbusRuleType = lib.types.submodule {
    options = {
      target = lib.mkOption { type = dbusTargetType; };
      comment = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
      };
    };
  };

  ruleType = lib.types.submodule {
    options = {
      host = lib.mkOption { type = lib.types.str; };
      port = lib.mkOption { type = lib.types.port; };
    };
  };

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
    extraPkgs = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
    };
    runtimeReadonlyDirs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = agentSandboxLib.defaultRuntimeReadonlyDirs;
    };
    devicePaths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = agentSandboxLib.defaultDevicePaths;
      description = ''
        Extra device nodes to bind into the jail (rw). Standard NVIDIA devices
        (including nvidia-fs when enabled) are bound automatically.
      '';
    };
    blockEnvVars = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = agentSandboxLib.defaultBlockEnvVars;
    };
    exposeWorkingDirectory = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
    extraBwrapArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
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
  };

  cfg = config.agent-sandbox;

  policyContextEnabled =
    cfg.network.enable || cfg.gates.filesystem.enable || cfg.sudoPolicy == "approve";

  sharedRuntimeReadonly = lib.optional cfg.network.enable "/run/netns";
  runtime = agentSandboxLib.mkRuntime {
    rootCfg = cfg;
    netnsEnter = "${config.security.wrapperDir}/agent-sandbox-enter";
  };

  mergePackageMounts =
    pkgCfg:
    pkgCfg
    // {
      readonlyDirs = lib.unique (cfg.readonlyDirs ++ sharedRuntimeReadonly ++ pkgCfg.readonlyDirs);
      readwriteDirs = lib.unique (cfg.readwriteDirs ++ pkgCfg.readwriteDirs);
      readonlyFiles = lib.unique (cfg.readonlyFiles ++ pkgCfg.readonlyFiles);
      readwriteFiles = lib.unique (cfg.readwriteFiles ++ pkgCfg.readwriteFiles);
      hiddenPaths = lib.unique (cfg.hiddenPaths ++ pkgCfg.hiddenPaths);
    };

  sudoGuardPkg = import ./sudo-guard.nix {
    inherit pkgs policyPkg;
    policy = cfg.sudoPolicy;
  };

  wrapOne =
    value:
    agentSandboxLib.mkWrapPackage pkgs (
      mergePackageMounts value
      // {
        inherit (cfg.wrapping) replaceOriginalBinary unsafeAliasPrefix;
        inherit runtime;
        inherit (runtime)
          policySocket
          sandboxPolicySocket
          policyContext
          network
          dbus
          ;
        dbusProxyPkg = policyPkg;
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
  credentialPathValid =
    path:
    path == null || (lib.hasPrefix "/" path && !(lib.hasInfix "\n" path) && !(lib.hasInfix "\r" path));
  cidrValid = value: builtins.match "^.+/.+$" value != null;

in
{
  options.agent-sandbox = {
    enable = lib.mkEnableOption "jail.nix bubblewrap sandbox + optional network policy for AI agent CLIs";

    packages = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule { options = packageOptions; });
      default = [ ];
      description = "Agent packages wrapped for sandboxed execution.";
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
        only; ``-u`` / ``-E`` and similar flags are not supported. The host\'s
        ``/run/wrappers/bin/sudo`` is left untouched.
      '';
    };

    policy = {
      socketPath = lib.mkOption {
        type = lib.types.str;
        default = "/run/agent-sandbox/policy.sock";
      };
      sandboxSocketPath = lib.mkOption {
        type = lib.types.str;
        default = "/run/agent-sandbox/sandbox-policy.sock";
        description = "Sandbox-facing policyd socket. Bound over policy.socketPath inside sandboxes.";
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
      interactiveApproval = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          When true, unknown hosts block in policyd until the UI allows or denies
          (same flow as elevation). Host-side OMP extension, ``agent-sandbox-ui``,
          or ``agent-sandbox-approve`` may approve from the host policy socket.
        '';
      };
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
    };

    network = {
      enable = lib.mkEnableOption "deny-by-default network via netns + NFQUEUE policy enforcement";

      netnsName = lib.mkOption {
        type = lib.types.str;
        default = "agent-sandbox";
      };

      queueNumber = lib.mkOption {
        type = lib.types.int;
        default = 0;
        description = "NFQUEUE number used by nftables and agent-sandbox-nfq.";
      };

      hostIp = lib.mkOption {
        type = lib.types.str;
        default = "169.254.100.1";
      };
      netnsIp = lib.mkOption {
        type = lib.types.str;
        default = "169.254.100.2";
      };
      vethHost = lib.mkOption {
        type = lib.types.str;
        default = "asbx-host";
      };
      vethNetns = lib.mkOption {
        type = lib.types.str;
        default = "asbx-ns";
      };
      hostIp6 = lib.mkOption {
        type = lib.types.str;
        default = "fd00:dead:beef::1";
        description = "IPv6 host-side veth address (stable ULA).";
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

      declarativeAllow = lib.mkOption {
        type = lib.types.listOf ruleType;
        default = [ ];
        description = "Hosts allowed without interactive approval (merged under user/project policy).";
      };

      declarativeDeny = lib.mkOption {
        type = lib.types.listOf ruleType;
        default = [ ];
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

      dnsForwardTarget = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.53:53";
        description = ''
          Upstream DNS server used by agent-sandbox-dns-forwarder for raw DNS
          forwarding. Defaults to the systemd-resolved stub on the host.
        '';
      };
      httpProxy = {
        enable = lib.mkEnableOption "transparent HTTP interception through the trusted proxy RPC";
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

        wireguardPort = lib.mkOption {
          type = lib.types.ints.between 1 65535;
          default = 51820;
          description = "UDP port used by mitmproxy's WireGuard listener.";
        };

        proxyHostIp = lib.mkOption {
          type = lib.types.str;
          default = "169.254.100.1";
          description = "Host IPv4 address at which the proxy WireGuard peer is reachable.";
        };

        upstreamAllowCidrs = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "Additional CIDRs the dedicated proxy UID may reach directly.";
        };

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

        socketPath = lib.mkOption {
          type = lib.types.str;
          default = "/run/agent-sandbox/proxy-policy.sock";
          description = "Unix socket exposed to the trusted transparent HTTP proxy.";

        };

        gid = lib.mkOption {
          type = lib.types.nullOr lib.types.int;
          default = null;
          description = "Optional explicit group ID allowed to connect to the trusted proxy socket; null uses the dedicated proxy group.";
        };

      };
    };
    gates = {
      filesystem = {
        enable = lib.mkEnableOption ''
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
      };
      resources = {
        enable = lib.mkEnableOption ''
          seccomp-backed resource gates for all AF_UNIX sockets and
          broker-opened host device nodes under /dev in dynamic filesystem mode.
          Requires gates.filesystem.enable.
        '';
      };
      syscalls = {
        enable = lib.mkEnableOption ''
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
            urls = map (rule: rule.url) (proxy.declarativeAllow ++ proxy.declarativeDeny);
            suffix = lib.optionalString (urls != [ ]) " (configured URLs: ${lib.concatStringsSep ", " urls})";
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
    ];
    environment.systemPackages = (map wrapOne cfg.packages) ++ [
      policyPkg
    ];

    # Propagate UI backend choice to session so manually run agent-sandbox-ui
    # picks up the configured backend without needing the service environment.
    environment.sessionVariables = {
      AGENT_SANDBOX_UI_BACKEND = cfg.policy.uiBackend;
    };

    nixpkgs.overlays = lib.mkAfter [
      (final: _: {
        agentSandbox = {
          inherit (agentSandboxLib)
            mkWrapPackage
            defaultCommonPkgs
            defaultBlockEnvVars
            defaultRuntimeReadonlyDirs
            defaultDevicePaths
            ;
          wrapPackage = agentSandboxLib.mkWrapPackage final;
          inherit policyPkg;
        };
      })
    ];
  };
}
