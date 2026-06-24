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
  };

  cfg = config.agent-sandbox;

  policyContextEnabled =
    cfg.network.enable || cfg.filesystem.dynamicApproval.enable || cfg.sudoPolicy == "approve";

  sharedRuntimeReadonly = lib.optional cfg.network.enable "/run/netns";

  mergePackageMounts =
    pkgCfg:
    pkgCfg
    // {
      readonlyDirs = lib.unique (cfg.readonlyDirs ++ sharedRuntimeReadonly ++ pkgCfg.readonlyDirs);
      readwriteDirs = lib.unique (cfg.readwriteDirs ++ pkgCfg.readwriteDirs);
      readonlyFiles = lib.unique (cfg.readonlyFiles ++ pkgCfg.readonlyFiles);
      readwriteFiles = lib.unique (cfg.readwriteFiles ++ pkgCfg.readwriteFiles);
    };

  networkConfig =
    if cfg.network.enable then
      {
        netnsName = cfg.network.netnsName;
        netnsEnter = "${config.security.wrapperDir}/agent-sandbox-enter";
      }
    else
      null;

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
        policySocket = cfg.policy.socketPath;
        sandboxPolicySocket = cfg.policy.sandboxSocketPath;
        policyContext = policyContextEnabled;
        network = networkConfig;
        sudoGuard = sudoGuardPkg;
      }
      // lib.optionalAttrs cfg.filesystem.dynamicApproval.enable {
        inherit fsArmPkg;
      }
      // lib.optionalAttrs (cfg.syscallGate.enable && cfg.network.enable) {
        inherit syscallArmPkg;
      }
    );
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
      default = "approve";
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
          DNS target for the host NAT route_localnet check. The DNS forwarder
          runs inside the netns on 127.0.0.53:53 and forwards to 1.1.1.1:53.
        '';
      };
    };
    filesystem = {
      dynamicApproval = {
        enable = lib.mkEnableOption ''
          kernel-mediated dynamic filesystem access approval via fanotify.
          Controls filesystem access at runtime using path-based allow/deny rules.
          The first process inside each sandbox becomes agent-sandbox-fs-arm,
          which requests a fanotify monitor from policyd before execing the real entry.
          Static bubblewrap mounts remain the structural write boundary.
          Disabled by default. When disabled, no fs-arm helper or fsmon process
          is used and there is no kernel-level filesystem mediation.
        '';
      };
    };

    syscallGate = {
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
  }
  // mountOptions;

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = policyContextEnabled -> cfg.policy.socketPath != cfg.policy.sandboxSocketPath;
        message = "agent-sandbox.policy.socketPath and sandboxSocketPath must differ when policy is enabled";
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
