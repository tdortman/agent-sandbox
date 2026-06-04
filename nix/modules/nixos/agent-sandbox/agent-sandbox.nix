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
    jail-nix = inputs.jail-nix;
  };

  policyPkg = inputs.self.packages.${pkgs.system}.agent-sandbox;

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
    package = lib.mkPackageOption pkgs "llm-agents" { };
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
    exposeWorkingDirectory = lib.mkOption { type = lib.types.bool; default = true; };
    extraBwrapArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
    };
  };

  cfg = config.agent-sandbox;

  sharedRuntimeReadonly =
    lib.optional cfg.network.enable "/run/agent-sandbox"
    ++ lib.optional cfg.network.enable "/run/netns";

  mergePackageMounts = pkgCfg:
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
        proxyUrl = cfg.network.proxyUrl;
        netnsEnter = "${config.security.wrapperDir}/agent-sandbox-enter";
        injectProxyEnv = cfg.network.injectProxyEnv;
      }
    else
      null;

  sudoGuardPkg = import ./sudo-guard.nix {
    inherit pkgs policyPkg;
    policy = cfg.sudoPolicy;
  };

  wrapOne = value:
    agentSandboxLib.mkWrapPackage pkgs (
      mergePackageMounts value
      // {
        inherit (cfg.wrapping) replaceOriginalBinary unsafeAliasPrefix;
        policySocket = cfg.policy.socketPath;
        network = networkConfig;
        sudoGuard = sudoGuardPkg;
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
      type = lib.types.enum [ "deny" "approve" ];
      default = "approve";
      description = ''
        How sandboxed agents may invoke sudo. ``deny`` blocks elevation.
        ``approve`` replaces sudo with a shim that requests policy UI approval via policyd,
        then runs the approved command as root on the host (not inside bubblewrap).
        OMP extension or ``agent-sandbox-ui``. v1: ``sudo <cmd> [args…]``
        only; ``-u`` / ``-E`` and similar flags are not supported.
      '';
    };

    policy = {
      socketPath = lib.mkOption {
        type = lib.types.str;
        default = "/run/agent-sandbox/policy.sock";
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
          (same flow as elevation). OMP extension and/or ``agent-sandbox-ui``.
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
        '';
      };
    };

    network = {
      enable = lib.mkEnableOption "deny-by-default network via netns + policy proxy";

      netnsName = lib.mkOption {
        type = lib.types.str;
        default = "agent-sandbox";
      };

      proxyUrl = lib.mkOption {
        type = lib.types.str;
        default = "http://127.0.0.1:17888";
        description = "Forced HTTP CONNECT proxy URL injected into wrapped agents.";
      };

      proxyAddress = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.1:17888";
        description = ''
          host:port where the policy proxy listens inside the ``agent-sandbox`` netns.
          Loopback keeps nftables DNAT and ``SO_ORIGINAL_DST`` in the same namespace.
        '';
      };

      hostIp = lib.mkOption { type = lib.types.str; default = "169.254.100.1"; };
      netnsIp = lib.mkOption { type = lib.types.str; default = "169.254.100.2"; };
      vethHost = lib.mkOption { type = lib.types.str; default = "asbx-host"; };
      vethNetns = lib.mkOption { type = lib.types.str; default = "asbx-ns"; };

      declarativeAllow = lib.mkOption {
        type = lib.types.listOf ruleType;
        default = [
          # LLM / agent APIs
          { host = "api.openai.com"; port = 443; }
          { host = "chatgpt.com"; port = 443; }
          { host = "api.deepseek.com"; port = 443; }
          { host = "*.anthropic.com"; port = 443; }
          { host = "api.githubcopilot.com"; port = 443; }
          { host = "*.githubcopilot.com"; port = 443; }
          { host = "generativelanguage.googleapis.com"; port = 443; }
          { host = "api.mistral.ai"; port = 443; }
          { host = "api.cohere.ai"; port = 443; }
          { host = "api.together.xyz"; port = 443; }
          { host = "openrouter.ai"; port = 443; }
          { host = "api.morphllm.com"; port = 443; }
          { host = "*.amazonaws.com"; port = 443; }
          { host = "opencode.ai"; port = 443; }
          { host = "api.opencode.ai"; port = 443; }
          { host = "ampcode.com"; port = 443; }
          { host = "*.ampcode.com"; port = 443; }
          { host = "*.factory.ai"; port = 443; }
          { host = "api.workos.com"; port = 443; }
          { host = "*.cursor.sh"; port = 443; }
          { host = "data.charm.land"; port = 443; }
          { host = "catwalk.charm.sh"; port = 443; }
          { host = "models.dev"; port = 443; }
          # Git / source hosts
          { host = "github.com"; port = 443; }
          { host = "api.github.com"; port = 443; }
          { host = "raw.githubusercontent.com"; port = 443; }
          { host = "codeload.github.com"; port = 443; }
          { host = "objects.githubusercontent.com"; port = 443; }
          { host = "release-assets.githubusercontent.com"; port = 443; }
          { host = "gitlab.com"; port = 443; }
          # Package registries
          { host = "registry.npmjs.org"; port = 443; }
          { host = "*.npmjs.org"; port = 443; }
          { host = "registry.yarnpkg.com"; port = 443; }
          { host = "pypi.org"; port = 443; }
          { host = "files.pythonhosted.org"; port = 443; }
          { host = "crates.io"; port = 443; }
          { host = "static.crates.io"; port = 443; }
          { host = "index.crates.io"; port = 443; }
          { host = "proxy.golang.org"; port = 443; }
          { host = "sum.golang.org"; port = 443; }
          { host = "formulae.brew.sh"; port = 443; }
          # Nix
          { host = "cache.nixos.org"; port = 443; }
        ];
        description = "Hosts allowed without interactive approval (merged under user/project policy).";
      };

      declarativeDeny = lib.mkOption {
        type = lib.types.listOf ruleType;
        default = [ ];
      };

      transparentRedirect = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          DNAT outbound TCP 80/443 in the sandbox netns to the policy proxy.
          Apps do not need to honor HTTP_PROXY; the proxy learns the real destination
          via SO_ORIGINAL_DST and tunnels after policy approval.
        '';
      };

      injectProxyEnv = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Set HTTP_PROXY/HTTPS_PROXY for clients that support explicit proxies.
          Transparent redirect remains the enforcement path when enabled.
        '';
      };

      policyTimeout = lib.mkOption {
        type = lib.types.float;
        default = 35.0;
        description = ''
          Max seconds the policy proxy waits for policyd per connection check.
          When interactive approval is enabled, the proxy uses at least
          ``agent-sandbox.policy.approvalTimeout`` so blocking prompts can complete.
        '';
      };

      dnsForwardTarget = lib.mkOption {
        type = lib.types.str;
        default = "127.0.0.53:53";
        description = ''
          Host resolver the veth-gateway DNS proxy forwards to.
          Use the systemd-resolved stub (127.0.0.53:53) so sandboxes inherit host
          resolver behavior (split DNS, VPN, NextDNS, etc.). Sandboxes use nameserver 169.254.100.1.
        '';
      };
    };
  } // mountOptions;

  config = lib.mkIf cfg.enable {
    environment.systemPackages =
      (map wrapOne cfg.packages)
      ++ [
        policyPkg
      ];

    nixpkgs.overlays = lib.mkAfter [
      (final: prev: {
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
