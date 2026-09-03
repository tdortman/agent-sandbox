{
  lib,
  jail-nix,
}:
let
  buildPermissions =
    c:
    {
      blockEnvVars ? defaultBlockEnvVars,
      commonPkgs ? defaultCommonPkgs,
      devicePaths ? defaultDevicePaths,
      dynamicFs ? false,
      exposeWorkingDirectory ? true,
      extraBwrapArgs ? [ ],
      extraPkgs ? [ ],
      packageName ? null,
      policyContext ? false,
      policyPkg ? null,
      policySocket ? null,
      readonlyDirs ? [ ],
      readonlyFiles ? [ ],
      readwriteDirs ? [ ],
      readwriteFiles ? [ ],
      registerCommand ? "",
      runtime ? null,
      runtimeReadonlyDirs ? defaultRuntimeReadonlyDirs,
      sudoGuard ? null,
      ...
    }@cfg:
    let
      absReadonly = readonlyDirs'.abs ++ readonlyFiles'.abs;
      absReadwrite = readwriteDirs'.abs ++ readwriteFiles'.abs;
      homeReadonly = readonlyDirs'.home ++ readonlyFiles'.home;
      homeReadwrite = readwriteDirs'.home ++ readwriteFiles'.home;
      # In dynamic-FS mode the full host filesystem is visible via --bind / /.
      # All bind-mount combinators are redundant and broken (bwrap cannot mkdir
      # through symlinks on a root-bound tree), so we skip them entirely.
      inheritShell = if dynamicFs then c.inherit-shell-env-dynamic else c.inherit-shell-env;
      readonlyDirs' = splitMountPaths readonlyDirs;
      readonlyFiles' = splitMountPaths readonlyFiles;
      readwriteDirs' = splitMountPaths readwriteDirs;
      readwriteFiles' = splitMountPaths readwriteFiles;
      # sudoGuard must be in sandboxPkgs (add-pkg-deps), not only add-runtime PATH:
      # policyd-built shells build PATH from package deps, not the jail launcher exports.
      sandboxPkgs = lib.unique (
        [ cfg.package ] ++ commonPkgs ++ extraPkgs ++ lib.optionals (sudoGuard != null) [ sudoGuard ]
      );
    in
    with c;
    [
      (block-env-vars blockEnvVars)
      inheritShell
      (add-pkg-deps sandboxPkgs)
    ]
    ++ lib.optionals (!dynamicFs && exposeWorkingDirectory) [ mount-cwd ]
    ++ lib.optionals (!dynamicFs) (map try-readonly (lib.unique (runtimeReadonlyDirs ++ absReadonly)))
    ++ lib.optionals (!dynamicFs) (map try-readwrite absReadwrite)
    ++ lib.optionals (!dynamicFs) [
      (home-readonly-mounts homeReadonly)
      (home-readwrite-mounts homeReadwrite)
    ]
    ++ lib.optionals (runtime != null && runtime.policyContext) [
      (agent-sandbox-context-env { inherit runtime; })
    ]
    ++ lib.optionals (policyContext && policyPkg != null && policySocket != null) [
      (agent-sandbox-register-sandbox {
        inherit packageName policySocket registerCommand;
      })
    ]
    ++ lib.optionals (runtime != null && runtime.network != null) [
      (if dynamicFs then c.agent-sandbox-restricted-net-dynamic else agent-sandbox-restricted-net)
    ]
    ++ lib.optionals (sudoGuard != null) [
      (agent-sandbox-sudo-guard sudoGuard)
    ]
    ++ map unsafe-add-raw-args extraBwrapArgs
    ++ lib.optionals (!dynamicFs && exposeWorkingDirectory) [ c.rebind-cwd ]
    ++ [
      agent-sandbox-nvidia-gpu
    ]
    ++ map try-dev-bind devicePaths
    ++ [
      (unsafe-add-raw-args "--dir /run")
      (unsafe-add-raw-args "--tmpfs /run/wrappers")
    ];
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
  defaultBlockEnvVars = [
    "AWS_ACCESS_KEY_ID"
    "AWS_SECRET_ACCESS_KEY"
    "AWS_SESSION_TOKEN"
    "GITHUB_TOKEN"
    "GH_TOKEN"
    "OPENAI_API_KEY"
    "ANTHROPIC_API_KEY"
    "CURSOR_API_KEY"
    "NIXOS_CONFIG_GITHUB_TOKEN"
  ];
  defaultCommonPkgs =
    pkgs: with pkgs; [
      bashInteractive
      curl
      wget
      jq
      git
      which
      ripgrep
      gnugrep
      gawkInteractive
      ps
      findutils
      gzip
      unzip
      gnutar
      diffutils
      gnused
    ];
  # Extra device nodes (agent-sandbox-nvidia-gpu binds the standard NVIDIA set).
  defaultDevicePaths = [ ];
  defaultRuntimeReadonlyDirs = [
    "/run/current-system"
    "/run/opengl-driver"
    "/run/opengl-driver-32"
  ];
  homeMountRel = path: if path == "~" then "" else lib.removePrefix "~/" path;
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
  isHomeMountPath = path: path == "~" || lib.hasPrefix "~/" path;
  isHostMountPath = path: lib.hasPrefix "/" path;
  mkRuntime =
    {
      rootCfg,
      netnsEnter ? null,
    }:
    let
      inherit (rootCfg) network policy;
      policyContext =
        network.enable
        || policy.dbus.enable
        || rootCfg.gates.filesystem.enable
        || rootCfg.sudoPolicy == "approve";
    in
    {
      inherit policyContext;

      inherit (policy)
        approvalTimeout
        autoSpawnPolicyUi
        exportedJson
        exportedNix
        interactiveApproval
        uiBackend
        ;

      inherit (network) hostIp hostIp6 queueNumber;
      inherit (network) dnsForwardTarget;
      inherit (policy) dbus;
      httpProxy = network.httpProxy or { enable = false; };

      network =
        if network.enable then
          {
            inherit (network)
              netnsIp
              netnsIp6
              netnsIp6Prefix
              netnsName
              vethHost
              vethNetns
              ;

            inherit netnsEnter;
          }
        else
          null;

      policySocket = policy.socketPath;
      policyTimeout = lib.max network.policyTimeout policy.approvalTimeout;
      sandboxPolicySocket = policy.sandboxSocketPath;
    };
  nvidiaSetupScript = bindDevices: ''
    ${lib.optionalString bindDevices ''
      for _gpu in /dev/nvidia*; do
        [[ -e "$_gpu" ]] || continue
        RUNTIME_ARGS+=(--dev-bind "$_gpu" "$_gpu")
      done
      if [[ -d /dev/nvidia-caps ]]; then
        for _cap in /dev/nvidia-caps/*; do
          [[ -e "$_cap" ]] || continue
          RUNTIME_ARGS+=(--dev-bind "$_cap" "$_cap")
        done
      fi
    ''}
    if [[ -d /run/opengl-driver/lib ]]; then
      _asbx_ld="/run/opengl-driver/lib"
      if [[ -n "''${LD_LIBRARY_PATH:-}" ]]; then
        case ":$LD_LIBRARY_PATH:" in
          *":$_asbx_ld:"*) ;;
          *) _asbx_ld="$_asbx_ld:$LD_LIBRARY_PATH" ;;
        esac
      fi
      RUNTIME_ARGS+=(--setenv LD_LIBRARY_PATH "$_asbx_ld")
    fi
  '';
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
  policyContextScript = ''
    # Reuse outer context if already set.
    if [[ -n "''${AGENT_SANDBOX_SESSION_ID:-}" ]]; then
      _agent_sandbox_session_id="$AGENT_SANDBOX_SESSION_ID"
    else
      IFS= read -r _agent_sandbox_session_id < /proc/sys/kernel/random/uuid
    fi
    if [[ -n "''${AGENT_SANDBOX_HOME:-}" ]]; then
      _agent_sandbox_home="$AGENT_SANDBOX_HOME"
    else
      _agent_sandbox_home=$(readlink -f "$HOME")
    fi
    if [[ -n "''${AGENT_SANDBOX_CWD:-}" ]]; then
      _agent_sandbox_cwd="$AGENT_SANDBOX_CWD"
    else
      _agent_sandbox_cwd="$PWD"
    fi
    if [[ -n "''${AGENT_SANDBOX_PROJECT_ROOT:-}" ]]; then
      _agent_sandbox_project_root="$AGENT_SANDBOX_PROJECT_ROOT"
    else
      _agent_sandbox_project_root="$PWD"
      if command -v git >/dev/null 2>&1; then
        _git_root="$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null)" || true
        [[ -n "$_git_root" ]] && _agent_sandbox_project_root="$_git_root"
      fi
    fi
    RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_CWD "$_agent_sandbox_cwd")
    RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_HOME "$_agent_sandbox_home")
    RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_PROJECT_ROOT "$_agent_sandbox_project_root")
    RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_SESSION_ID "$_agent_sandbox_session_id")
  '';
  splitMountPaths =
    paths:
    let
      invalid = lib.filter (p: !isHomeMountPath p && !isHostMountPath p) paths;
    in
    if invalid != [ ] then
      throw ''
        agent-sandbox: mount paths must start with ~/ or / (for example "~/.agents" or "/run/user/1000").
        Invalid: ${lib.concatStringsSep ", " (map (p: ''"${p}"'') invalid)}
      ''
    else
      {
        abs = lib.filter isHostMountPath paths;
        home = map homeMountRel (lib.filter isHomeMountPath paths);
      };

in
{
  inherit
    dbusRuleJson
    defaultBlockEnvVars
    defaultCommonPkgs
    defaultDevicePaths
    defaultRuntimeReadonlyDirs
    httpRuleJson
    mkRuntime
    packageHasPolicy
    ;

  mkWrapPackage =
    pkgs:
    {
      package,
      binary ? null,
      blockEnvVars ? defaultBlockEnvVars,
      commonPkgs ? defaultCommonPkgs pkgs,
      dbus ? null,
      dbusProxyPkg ? null,
      devicePaths ? defaultDevicePaths,
      exposeWorkingDirectory ? true,
      extraBwrapArgs ? [ ],
      extraPkgs ? [ ],
      filesystemGate ? false,
      fsArmPkg ? null,
      hiddenPaths ? [ ],
      network ? null,
      packageName ? if binary != null then binary else lib.baseNameOf (lib.getExe package),
      policyContext ? false,
      policyPkg ? null,
      policySocket ? null,
      readonlyDirs ? [ ],
      readonlyFiles ? [ ],
      readwriteDirs ? [ ],
      readwriteFiles ? [ ],
      replaceOriginalBinary ? true,
      resourceGate ? false,
      runtime ? null,
      runtimeReadonlyDirs ? defaultRuntimeReadonlyDirs,
      sandboxPolicySocket ? null,
      sudoGuard ? null,
      syscallArmPkg ? null,
      unsafeAliasPrefix ? "unsafe-",
    }:
    let
      agentCombinators = import ./combinators.nix {
        inherit lib pkgs policyContextScript;
        nvidiaSetupScript = nvidiaSetupScript true;
      } builtinCombinators;
      binName = if binary != null then binary else lib.baseNameOf (lib.getExe package);
      blockScript = lib.concatMapStringsSep "\n" (var: "unset ${var} || true") blockEnvVars;
      builtinCombinators = (jail-nix.lib.init pkgs).combinators;
      dbusCleanupScript = lib.optionalString dbusMode ''
        kill "$_asbx_dbus_pid" 2>/dev/null || true
        wait "$_asbx_dbus_pid" 2>/dev/null || true
        rm -rf "$_asbx_dbus_dir"
      '';
      dbusMode = dbus != null && dbus.enable && dbusProxyPkg != null;
      dbusScript = lib.optionalString dbusMode ''
        _asbx_dbus_root="${dbusSocketDirectory}/''${UID}"
        mkdir -p "$_asbx_dbus_root"
        _asbx_dbus_dir="$(mktemp -d "$_asbx_dbus_root/agent-sandbox-dbus.XXXXXX")"
        _asbx_dbus_socket="$_asbx_dbus_dir/session.sock"
        _asbx_dbus_upstream=${
          if dbusUpstreamAddress != null then
            lib.escapeShellArg dbusUpstreamAddress
          else
            ''"''${DBUS_SESSION_BUS_ADDRESS:-}"''
        }
        [[ -n "$_asbx_dbus_upstream" ]] || {
          echo "agent-sandbox D-Bus: DBUS_SESSION_BUS_ADDRESS is unset" >&2
          rm -rf "$_asbx_dbus_dir"
          exit 1
        }
        ${dbusProxyPkg}/bin/agent-sandbox-dbus-proxy \
          --listen "$_asbx_dbus_socket" \
          --upstream-address "$_asbx_dbus_upstream" \
          --policy-socket ${lib.escapeShellArg policySocket} \
          --bus session \
          --cwd "$_agent_sandbox_cwd" \
          --home "$_agent_sandbox_home" \
          --project-root "$_agent_sandbox_project_root" \
          --uid "$UID" \
          --sandbox-session-id "$_agent_sandbox_session_id" &
        _asbx_dbus_pid=$!
        trap '${dbusCleanupScript}' EXIT
        trap 'exit 143' INT TERM
        while [[ ! -S "$_asbx_dbus_socket" ]]; do
          if ! kill -0 "$_asbx_dbus_pid" 2>/dev/null; then
            wait "$_asbx_dbus_pid" || true
            echo "agent-sandbox D-Bus: relay failed to start" >&2
            rm -rf "$_asbx_dbus_dir"
            exit 1
          fi
          sleep 0.01
        done
        RUNTIME_ARGS+=(--ro-bind "$_asbx_dbus_dir" "$_asbx_dbus_dir")
        RUNTIME_ARGS+=(--setenv DBUS_SESSION_BUS_ADDRESS "unix:path=$_asbx_dbus_socket")
      '';
      dbusSocketDirectory = if dbus != null then dbus.socketDirectory else "/run/user";
      dbusUpstreamAddress = if dbus != null then dbus.upstreamAddress else null;
      deviceBindScript = lib.concatMapStringsSep "\n" (path: ''
        if [[ -e "${path}" ]]; then
          RUNTIME_ARGS+=(--dev-bind "${path}" "${path}")
        fi
      '') devicePaths;
      dnsEndpoint = if runtime != null && runtime.network != null then "${runtime.hostIp}:53" else null;
      dnsScript = lib.optionalString hasNetwork ''
        if [[ -f /etc/agent-sandbox/nsswitch.conf ]]; then
          _real_ns=$(readlink -f /etc/nsswitch.conf 2>/dev/null) || _real_ns=""
          if [[ -n "$_real_ns" ]]; then
            RUNTIME_ARGS+=(--ro-bind /etc/agent-sandbox/nsswitch.conf "$_real_ns")
          fi
        fi
        if [[ -f /etc/agent-sandbox/resolv.conf ]]; then
          # The resolved symlink target may be inside /run (tmpfs in bwrap).
          # Write a temp file and bind-mount to the resolved path, creating
          # the parent directory first so the mount point exists.
          _asbx_resolv_tmp=$(mktemp)
          cp /etc/agent-sandbox/resolv.conf "$_asbx_resolv_tmp"
          _real_resolv=$(readlink -f /etc/resolv.conf 2>/dev/null) || _real_resolv=""
          if [[ -n "$_real_resolv" ]]; then
            mkdir -p "$(dirname "$_real_resolv")"
            RUNTIME_ARGS+=(--ro-bind "$_asbx_resolv_tmp" "$_real_resolv")
          fi
        fi
        if [[ -d /run/nscd ]]; then
          RUNTIME_ARGS+=(--tmpfs /run/nscd)
        fi
      '';
      dynamicFs = fsArmPkg != null;
      dynamicInner = pkgs.writeShellApplication {
        name = sandboxedName;

        runtimeInputs = [
          pkgs.bubblewrap
          pkgs.coreutils
        ];

        text = ''
          RUNTIME_ARGS=()

          if [ ! -e ~/.local/share/jail.nix/passwd ] || [ ! -e ~/.local/share/jail.nix/group ]; then
            NOLOGIN=${pkgs.shadow}/bin/nologin
            mkdir -p ~/.local/share/jail.nix
            echo "root:x:0:0:System administrator:/root:$NOLOGIN" > ~/.local/share/jail.nix/passwd
            echo "$(id -un):x:$(id -u):$(id -g)::$HOME:$NOLOGIN" >> ~/.local/share/jail.nix/passwd
            echo "root:x:0:" > ~/.local/share/jail.nix/group
            echo "$(id -gn):x:$(id -g):" >> ~/.local/share/jail.nix/group
          fi

          ${blockScript}

          while IFS= read -r -d $'\0' _asbx_line; do
            case "$_asbx_line" in
              *=*) ;;
              *) continue ;;
            esac
            _asbx_name="''${_asbx_line%%=*}"
            _asbx_val="''${_asbx_line#*=}"
            case "$_asbx_name" in
              *[!A-Za-z0-9_]*|"") continue ;;
              TMPDIR|TEMP|TMP|PATH) continue ;;
            esac
            RUNTIME_ARGS+=(--setenv "$_asbx_name" "$_asbx_val")
          done < <(env -0)

          ${policyScript}
          ${registerSandboxScript}
          ${dbusScript}
          ${dnsScript}

          ${nvidiaSetupScript (!resourceGate)}
          ${lib.optionalString (!resourceGate) deviceBindScript}

          ${networkModeScript}
          ${fsArmScript}
          ${hidePathsScript}
          ${proxyTrustScript}


          ${freezeLaunchPrefix}${pkgs.bubblewrap}/bin/bwrap \
            --bind / / \
            --tmpfs /tmp \
            --proc /proc \
            --dev-bind /dev /dev \
            --clearenv \
            --ro-bind ~/.local/share/jail.nix/passwd /etc/passwd \
            --ro-bind ~/.local/share/jail.nix/group /etc/group \
            ${lib.optionalString hasNetwork "--disable-userns"} \
            ${namespaceFlags} \
            --new-session --die-with-parent \
            ${extraBwrapStr} \
            --setenv TERM "''${TERM:-xterm}" \
            --setenv PATH "${sandboxPathStr}:$PATH" \
            --setenv LANG "''${LANG:-C.UTF-8}" \
            --setenv HOME "$HOME" \
            "''${RUNTIME_ARGS[@]}" \
            -- ${entryCmd} "$@"
          _asbx_status=$?
          exit "$_asbx_status"
        '';
      };
      dynamicLauncher =
        if hasNetwork then
          pkgs.writeShellApplication {
            name = sandboxedName;

            runtimeInputs = [
              pkgs.coreutils
              pkgs.gawk
            ];

            text = ''
              ${netnsEnterPrefix (lib.getExe dynamicInner)}
            '';
          }
        else
          dynamicInner;
      entryBase =
        if fsArmPkg != null then
          "${fsArmPkg}/bin/agent-sandbox-fs-arm -- ${lib.getExe package}"
        else
          lib.getExe package;
      entryCmd = "${syscallArmPrefix} ${entryBase}";
      entryPackage =
        if syscallGate || fsArmPkg != null then
          pkgs.writeShellScriptBin binName ''
            exec ${syscallArmPrefix} ${entryBase} "$@"
          ''
        else
          package;
      extraBwrapStr = lib.concatStringsSep " " extraBwrapArgs;
      extraPkgs' =
        extraPkgs
        ++ lib.optionals (fsArmPkg != null) [ fsArmPkg ]
        ++ lib.optionals (syscallArmPkg != null) [ syscallArmPkg ];
      finalLauncher = scopedLauncher;
      freezeLaunchPrefix = lib.optionalString freezeNeedsScope "${pkgs.systemd}/bin/systemd-run --user --scope --quiet --collect --expand-environment=no --unit=\"agent-sandbox-$$_$RANDOM.scope\" -- ";
      freezeNeedsScope = dbusMode || proxyMode;
      fsArmScript = lib.optionalString (fsArmPkg != null) ''
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_FS_STATIC_ALLOW ${staticAllowJsonArg})
      '';
      # ---- Dynamic-FS direct wrapper (bypasses jail-nix entirely) ----
      # When dynamic FS approval is active, --bind / / exposes the full host
      # filesystem.  Sandbox-private /proc and /tmp overlay that bind.  Every
      # jail-nix bind-mount combinator is both redundant and broken (bwrap
      # cannot mkdir through symlinks on a root-bound tree).  Generate the
      # wrapper directly to guarantee zero unexpected bind mounts.
      hasNetwork = network != null;
      # Mask paths so the sandbox cannot see their contents even though the
      # dynamic-FS wrapper binds the whole host root. Resolve existing symlinks
      # before adding mounts because bubblewrap destinations cannot traverse a
      # symlink; this also masks the object reached through aliases such as
      # NixOS-managed files under /etc. Directories are shadowed with an empty
      # tmpfs, files with /dev/null. Appended after all other mounts so nothing
      # re-exposes them. Entries may start with `~/` to refer to the invoking
      # user's home (expanded at wrapper generation time so the runtime script
      # never contains bare `~`, which shellcheck rejects).
      hidePathAssignment =
        path:
        if path == "~" then
          ''_asbx_hide="$HOME"''
        else if lib.hasPrefix "~/" path then
          ''_asbx_hide="$HOME/${lib.removePrefix "~/" path}"''
        else
          "_asbx_hide=${lib.escapeShellArg path}";
      hidePathsScript = ''
        RUNTIME_ARGS+=(--tmpfs /run/wrappers)
      ''
      +
        lib.concatMapStringsSep "\n"
          (path: ''
              ${hidePathAssignment path}
            _asbx_hide_target=""
            if [[ -e "$_asbx_hide" ]]; then
              _asbx_hide_target="$(readlink -f -- "$_asbx_hide" 2>/dev/null)" || _asbx_hide_target=""
            fi
            if [[ -d "$_asbx_hide_target" ]]; then
              RUNTIME_ARGS+=(--tmpfs "$_asbx_hide_target")
            elif [[ -e "$_asbx_hide_target" ]]; then
              RUNTIME_ARGS+=(--ro-bind /dev/null "$_asbx_hide_target")
            fi
          '')
          (
            [
              # The declarative policy inputs under /etc/agent-sandbox are
              # NixOS-managed symlinks into /nix/store, which the static allow
              # list serves without a policy check. Mask the whole directory so
              # the sandbox cannot read the declared policy files at any path.
              "/etc/agent-sandbox"
            ]
            ++ hiddenPaths
          );
      http3UdpProxyPorts =
        if runtime == null then
          "443"
        else
          let
            http3 =
              runtime.httpProxy.http3 or {
                altUdpPorts = [ ];
                udpPort = 443;
              };
          in
          lib.concatStringsSep " " ([ (toString http3.udpPort) ] ++ map toString http3.altUdpPorts);
      jailFn = jail-nix.lib.extend {
        inherit pkgs;
        additionalCombinators = _: agentCombinators;

        basePermissions =
          c:
          with c;
          [
            (if dynamicFs then agent-sandbox-dynamic-base else agent-sandbox-base)
          ]
          ++ lib.optionals (!dynamicFs) [
            bind-nix-store-runtime-closure
          ]
          ++ [
            fake-passwd
          ];
      };
      jailedDrv = jailFn sandboxedName entryPackage permissions;
      launcher =
        if dynamicFs then
          dynamicLauncher
        else if network != null then
          pkgs.writeShellApplication {
            name = sandboxedName;

            runtimeInputs = [
              pkgs.coreutils
              pkgs.gawk
            ];

            text = ''
              ${netnsEnterPrefix (lib.getExe jailedDrv)}
            '';
          }
        else
          jailedDrv;
      namespaceFlags =
        if hasNetwork then
          "--unshare-user --unshare-ipc --unshare-uts --unshare-cgroup"
        else
          "--unshare-user --unshare-ipc --unshare-pid --unshare-net --unshare-uts --unshare-cgroup";
      # Skip the netns-enter capability wrapper when the caller is already
      # inside the target network namespace. The NixOS wrapper backing
      # netnsEnter uses file capabilities, which the kernel refuses to grant
      # under NoNewPrivileges: a nested launch (a sandboxed agent spawning
      # another one) already runs inside the sandbox netns, so its setns is a
      # no-op yet the wrapper still aborts with "failed to inherit
      # capabilities" before the Rust body runs. Compare namespace identity
      # via the /proc/self/ns/net link and the /run/netns/<name> bind-mount
      # inode (both are the nsfs inode) and exec the inner directly when they
      # match; otherwise keep the privileged enter path.
      netnsEnterPrefix = inner: ''
        set -euo pipefail

        _asbx_target="$(stat -c %i ${lib.escapeShellArg "/run/netns/${network.netnsName}"} 2>/dev/null || true)"
        _asbx_current="$(readlink /proc/self/ns/net 2>/dev/null || true)"

        # Bypass the enter wrapper only when the caller is already inside the
        # target namespace AND holds no effective/ambient capabilities. The
        # nested case (a sandboxed agent, whose NoNewPrivileges suppresses
        # file capabilities) has both: setns is a no-op, so enter's remaining
        # work is its capability drop, and with nothing in the sets there is
        # nothing to drop. A privileged caller already in the namespace must
        # NOT bypass: enter clears its elevated ambient+effective caps so
        # bubblewrap runs unprivileged.
        _asbx_eff="$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || true)"
        _asbx_amb="$(awk '/^CapAmb:/{print $2}' /proc/self/status 2>/dev/null || true)"

        if [[ -n "$_asbx_target" && "$_asbx_current" == "net:[$_asbx_target]" && "$_asbx_eff" == "0000000000000000" && "$_asbx_amb" == "0000000000000000" ]]; then
          exec ${inner} "$@"
        fi

        # Joining the namespace from elsewhere needs CAP_SYS_ADMIN for setns.
        # NoNewPrivileges (inherited from an external launcher such as a
        # terminal or agent host) one-way suppresses the wrapper's file
        # capabilities, so a direct join aborts with the opaque NixOS wrapper
        # error "failed to inherit capabilities". Escape NNP through a systemd
        # user transient service: it runs as a child of the systemd user
        # manager, which does not inherit the caller's NNP, so the wrapper's
        # file capabilities apply again and the host-to-sandbox setns works.
        # A service does not inherit the caller's environment or working
        # directory, so forward them explicitly.
        _asbx_nnp="$(awk '/^NoNewPrivs:/{print $2}' /proc/self/status 2>/dev/null || true)"

        if [[ "$_asbx_nnp" == "1" && -n "$_asbx_target" && "$_asbx_current" != "net:[$_asbx_target]" ]]; then
          echo "agent-sandbox: NoNewPrivileges detected; joining namespace via systemd user service" >&2
          _asbx_sd_args=(--user --quiet --collect --pipe --wait --service-type=exec --expand-environment=no)
          while IFS= read -r -d $'\0' _asbx_line; do
            case "$_asbx_line" in
              *=*) ;;
              *) continue ;;
            esac
            _asbx_name="''${_asbx_line%%=*}"
            case "$_asbx_name" in
              *[!A-Za-z0-9_]*|""|TMPDIR|TEMP|TMP) continue ;;
            esac
            _asbx_sd_args+=(--setenv "$_asbx_line")
          done < <(env -0)
          _asbx_sd_args+=(--setenv "PATH=$PATH")
          _asbx_sd_args+=(--working-directory "$PWD")
          _asbx_sd_status=0
          if ${pkgs.systemd}/bin/systemd-run "''${_asbx_sd_args[@]}" -- ${lib.escapeShellArg network.netnsEnter} ${lib.escapeShellArg network.netnsName} ${inner} "$@"; then
            : # status already 0; the if guards systemd-run's exit against `set -e`
          else
            _asbx_sd_status=$?
          fi
          if [[ "$_asbx_sd_status" -ne 0 ]]; then
            echo "agent-sandbox: cannot join network namespace ${lib.escapeShellArg network.netnsName}: the launching process set NoNewPrivileges and the systemd user service fallback failed. Launch the sandboxed agent without NoNewPrivileges, or ensure a systemd user session is running." >&2
          fi
          exit "$_asbx_sd_status"
        fi

        exec ${lib.escapeShellArg network.netnsEnter} ${lib.escapeShellArg network.netnsName} ${inner} "$@"
      '';
      networkMode = if proxyMode then "proxy" else "direct";
      networkModeScript = lib.optionalString syscallGate ''
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_NETWORK_MODE ${lib.escapeShellArg networkMode})
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_UDP_PROXY_PORTS ${lib.escapeShellArg http3UdpProxyPorts})
        ${lib.optionalString (dnsEndpoint != null) ''
          RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_DNS_ENDPOINT ${lib.escapeShellArg dnsEndpoint})
        ''}
      '';
      permissions =
        buildPermissions (builtinCombinators // agentCombinators) {
          inherit
            blockEnvVars
            commonPkgs
            devicePaths
            dynamicFs
            exposeWorkingDirectory
            extraBwrapArgs
            extraPkgs
            fsArmPkg
            package
            packageName
            policyContext
            policyPkg
            policySocket
            readonlyDirs
            readonlyFiles
            readwriteDirs
            readwriteFiles
            registerCommand
            runtime
            sudoGuard
            syscallArmPkg
            ;

          runtimeReadonlyDirs = runtimeReadonlyDirs';
        }
        ++ lib.optionals (fsArmPkg != null) [
          (builtinCombinators.compose [
            (builtinCombinators.set-env "AGENT_SANDBOX_FS_STATIC_ALLOW" staticAllowJson)
            (builtinCombinators.add-runtime ''
              RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_FS_STATIC_ALLOW ${staticAllowJsonArg})
            '')
          ])
        ]
        ++ lib.optionals syscallGate [
          (builtinCombinators.compose [
            (builtinCombinators.set-env "AGENT_SANDBOX_NETWORK_MODE" networkMode)
            (builtinCombinators.set-env "AGENT_SANDBOX_UDP_PROXY_PORTS" http3UdpProxyPorts)
            (builtinCombinators.add-runtime ''
              RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_NETWORK_MODE ${lib.escapeShellArg networkMode})
              RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_UDP_PROXY_PORTS ${lib.escapeShellArg http3UdpProxyPorts})
            '')
          ])
        ]
        ++ lib.optionals (syscallGate && dnsEndpoint != null) [
          (builtinCombinators.compose [
            (builtinCombinators.set-env "AGENT_SANDBOX_DNS_ENDPOINT" dnsEndpoint)
            (builtinCombinators.add-runtime ''
              RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_DNS_ENDPOINT ${lib.escapeShellArg dnsEndpoint})
            '')
          ])
        ]
        ++ lib.optionals proxyMode [
          (builtinCombinators.compose [
            (builtinCombinators.set-env "SSL_CERT_FILE" proxyTrustBundle)
            (builtinCombinators.set-env "REQUESTS_CA_BUNDLE" proxyTrustBundle)
            (builtinCombinators.set-env "CURL_CA_BUNDLE" proxyTrustBundle)
            (builtinCombinators.set-env "NODE_EXTRA_CA_CERTS" proxyTrustBundle)
          ])
        ];
      policyScript =
        lib.optionalString (policyContext && policySocket != null && sandboxPolicySocket != null)
          ''
            ${policyContextScript}
            RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_POLICY_SOCKET ${lib.escapeShellArg sandboxPolicySocket})
            # Mask /run so unrelated host IPC sockets are invisible. With
            # resource gate, only /run/agent-sandbox is tmpfs'd; AF_UNIX
            # sockets remain visible from the host /run tree and are gated
            # by the broker. Otherwise, the entire /run is masked and safe
            # runtime directories are selectively rebound.
            ${runMaskScript}

            # The dynamic path bind-mounts the host root with --bind / /, so
            # the user's $HOME (including ~/.config/agent-sandbox) is fully
            # writable inside the sandbox by default. That breaks the trust
            # model: a compromised agent could rewrite trusted policy files to
            # add allow rules for itself. Rebind the logical config directory
            # read-only, and also rebind resolved policy symlink targets (or
            # their existing parents) read-only. A read-only bind on only the
            # symlink directory is not enough: writes through the symlink land
            # on the target path under the broad writable host-root bind.
            _asbx_user_config="$_agent_sandbox_home/.config/agent-sandbox"
            _asbx_policy_ro_binds=()
            _asbx_policy_candidates=()

            _asbx_ro_bind_once() {
              local _asbx_path="$1"
              local _asbx_bound
              [[ -n "$_asbx_path" && -e "$_asbx_path" ]] || return 0
              for _asbx_bound in "''${_asbx_policy_ro_binds[@]}"; do
                [[ "$_asbx_bound" == "$_asbx_path" ]] && return 0
              done
              _asbx_policy_ro_binds+=("$_asbx_path")
              RUNTIME_ARGS+=(--ro-bind "$_asbx_path" "$_asbx_path")
            }

            _asbx_existing_parent() {
              local _asbx_path="$1"
              while [[ "$_asbx_path" != "/" && ! -e "$_asbx_path" ]]; do
                _asbx_path="$(dirname "$_asbx_path")"
              done
              if [[ -e "$_asbx_path" ]]; then
                readlink -f "$_asbx_path" 2>/dev/null || true
              fi
            }

            _asbx_policy_target_parent() {
              local _asbx_policy_path="$1"
              local _asbx_policy_dir
              local _asbx_link_target
              local _asbx_target
              _asbx_policy_dir="$(dirname "$_asbx_policy_path")"
              if [[ -L "$_asbx_policy_path" ]]; then
                _asbx_link_target="$(readlink "$_asbx_policy_path")" || return 0
                case "$_asbx_link_target" in
                  /*) _asbx_target="$_asbx_link_target" ;;
                  *) _asbx_target="$_asbx_policy_dir/$_asbx_link_target" ;;
                esac
              else
                _asbx_target="$_asbx_policy_path"
              fi
              _asbx_existing_parent "$(dirname "$_asbx_target")"
            }

            if [[ -d "$_asbx_user_config" ]]; then
              _asbx_ro_bind_once "$_asbx_user_config"
            fi
            if [[ -e "$_asbx_user_config/policy.json" || -L "$_asbx_user_config/policy.json" ]]; then
              _asbx_policy_candidates+=("$_asbx_user_config/policy.json")
            fi
            # Package-specific policy files (home extension and package
            # project file) live under the config directories ro-bound
            # above, so the write-through risk is the symlink target path:
            # protect them exactly like the per-scope policy files above.
            _asbx_package_policy_home="$_asbx_user_config/packages/${lib.escapeShellArg packageName}.json"
            if [[ -e "$_asbx_package_policy_home" || -L "$_asbx_package_policy_home" ]]; then
              _asbx_policy_candidates+=("$_asbx_package_policy_home")
            fi
            _asbx_package_policy_project="$_agent_sandbox_project_root/.agent-sandbox/packages/${lib.escapeShellArg packageName}.json"
            if [[ -e "$_asbx_package_policy_project" || -L "$_asbx_package_policy_project" ]]; then
              _asbx_policy_candidates+=("$_asbx_package_policy_project")
            fi
            for _asbx_policy_candidate in "''${_asbx_policy_candidates[@]}"; do
              _asbx_policy_parent="$(_asbx_policy_target_parent "$_asbx_policy_candidate")"
              _asbx_ro_bind_once "$_asbx_policy_parent"
              if [[ -e "$_asbx_policy_candidate" ]]; then
                _asbx_policy_real="$(readlink -f "$_asbx_policy_candidate" 2>/dev/null)" || _asbx_policy_real=""
                _asbx_ro_bind_once "$_asbx_policy_real"
              fi
            done
            _asbx_project_agent_sandbox="$_agent_sandbox_project_root/.agent-sandbox"
            if [[ -d "$_asbx_project_agent_sandbox" ]]; then
              _asbx_ro_bind_once "$_asbx_project_agent_sandbox"
            fi
            _asbx_project_policy="$_asbx_project_agent_sandbox/policy.json"
            if [[ -e "$_asbx_project_policy" || -L "$_asbx_project_policy" ]]; then
              _asbx_policy_parent="$(_asbx_policy_target_parent "$_asbx_project_policy")"
              _asbx_ro_bind_once "$_asbx_policy_parent"
              _asbx_policy_real="$(readlink -f "$_asbx_project_policy" 2>/dev/null)" || _asbx_policy_real=""
              _asbx_ro_bind_once "$_asbx_policy_real"
            fi
            if [[ -f /run/agent-sandbox/dns-cache.json ]]; then
              RUNTIME_ARGS+=(--ro-bind /run/agent-sandbox/dns-cache.json /run/agent-sandbox/dns-cache.json)
            fi
            if [[ -f /run/agent-sandbox/session-context.json ]]; then
              RUNTIME_ARGS+=(--ro-bind /run/agent-sandbox/session-context.json /run/agent-sandbox/session-context.json)
            fi
            ${runReadonlyBindScript}
            ${runReadwriteBindScript}

            # Expose only the restricted sandbox request socket. The host
            # control socket stays hidden by tmpfs.
            RUNTIME_ARGS+=(--ro-bind-try ${lib.escapeShellArg sandboxPolicySocket} ${lib.escapeShellArg sandboxPolicySocket})
          '';
      proxyMode = runtime != null && runtime.httpProxy.enable;
      proxyTrustBundle = "/run/agent-sandbox/proxy-ca-bundle.pem";
      proxyTrustScript = lib.optionalString proxyMode ''
        [[ -f ${proxyTrustBundle} ]] || {
          echo "agent-sandbox proxy trust bundle is unavailable" >&2
          exit 1
        }
        RUNTIME_ARGS+=(--tmpfs /var/lib/agent-sandbox/proxy)
        RUNTIME_ARGS+=(--ro-bind ${proxyTrustBundle} ${proxyTrustBundle})
        RUNTIME_ARGS+=(--setenv SSL_CERT_FILE ${proxyTrustBundle})
        RUNTIME_ARGS+=(--setenv REQUESTS_CA_BUNDLE ${proxyTrustBundle})
        RUNTIME_ARGS+=(--setenv CURL_CA_BUNDLE ${proxyTrustBundle})
        RUNTIME_ARGS+=(--setenv NODE_EXTRA_CA_CERTS ${proxyTrustBundle})
      '';
      registerCommand = if policyPkg != null then "${policyPkg}/bin/agent-sandbox-approve" else "";
      registerSandboxScript =
        lib.optionalString (policyContext && policySocket != null && policyPkg != null)
          ''
            if [[ -n "''${_agent_sandbox_session_id:-}" && -S ${lib.escapeShellArg policySocket} ]]; then
              ${registerCommand} --socket ${lib.escapeShellArg policySocket} register-sandbox "$_agent_sandbox_session_id" --package ${lib.escapeShellArg packageName} --launcher-pid "$$" >/dev/null 2>&1 || true
            fi
          '';
      # Rebind explicit narrow /run/* mounts configured by the package
      # definition. Skip the broad /run path so the host's runtime sockets
      # stay hidden by the surrounding tmpfs.
      runBindScript =
        bindFlag: paths:
        lib.concatMapStringsSep "\n" (
          path:
          if path == "/run" then
            ""
          else
            ''
              if [[ -e "${path}" ]]; then
                RUNTIME_ARGS+=(${bindFlag} "${path}" "${path}")
              fi
            ''
        ) (lib.filter (p: lib.hasPrefix "/run/" p) (lib.unique paths));
      runMaskScript =
        if resourceGate then
          ''
            RUNTIME_ARGS+=(--tmpfs /run/agent-sandbox)
          ''
        else
          ''
            RUNTIME_ARGS+=(--tmpfs /run)
            for _asbx_safe_runtime in /run/current-system /run/opengl-driver /run/opengl-driver-32 /run/netns; do
              if [[ -e "$_asbx_safe_runtime" ]]; then
                RUNTIME_ARGS+=(--ro-bind "$_asbx_safe_runtime" "$_asbx_safe_runtime")
              fi
            done
            RUNTIME_ARGS+=(--tmpfs /run/agent-sandbox)
          '';
      runReadonlyBindScript = runBindScript "--ro-bind" (readonlyDirs ++ readonlyFiles);
      runReadwriteBindScript = runBindScript "--bind" (readwriteDirs ++ readwriteFiles);
      runtimeReadonlyDirs' = runtimeReadonlyDirs ++ lib.optionals proxyMode [ proxyTrustBundle ];
      sandboxPathStr = lib.makeBinPath sandboxPkgsList;
      sandboxPkgsList = lib.unique (
        [ package ] ++ commonPkgs ++ extraPkgs' ++ lib.optionals (sudoGuard != null) [ sudoGuard ]
      );
      sandboxedName = "sandboxed-${binName}";
      scopedLauncher =
        if freezeNeedsScope && !dynamicFs then
          pkgs.writeShellApplication {
            name = sandboxedName;

            text = ''
              set -euo pipefail
              exec ${pkgs.systemd}/bin/systemd-run --user --scope --quiet --collect --expand-environment=no \
                --unit="agent-sandbox-$$_$RANDOM.scope" -- ${lib.getExe launcher} "$@"
            '';
          }
        else
          launcher;
      staticAllowJson = builtins.toJSON staticAllowRules;
      staticAllowJsonArg = lib.escapeShellArg staticAllowJson;
      staticAllowRules = [
        {
          access = "all";
          path = "/nix/store";
        }
        {
          access = "all";
          path = "/tmp";
        }
      ]
      ++ (lib.lists.forEach (readonlyDirs ++ readonlyFiles) (path: {
        inherit path;
        access = "read";
      }))
      ++ (lib.lists.forEach (readwriteDirs ++ readwriteFiles) (path: {
        inherit path;
        access = "read_write";
      }));
      syscallArmPrefix =
        if syscallGate then
          lib.concatStringsSep " " (
            [
              "${syscallArmPkg}/bin/agent-sandbox-syscall-arm"
            ]
            ++ lib.optional filesystemGate "--filesystem"
            ++ [ "--" ]
          )
        else
          "";
      # Syscall gate: when wired, prepend `agent-sandbox-syscall-arm --` to
      # the entry chain. The arm helper installs a seccomp filter inside the
      # sandbox, then execs its argv tail. The chain is composable with the
      # fs-arm helper so dynamic-FS and syscall-gate can both be active.
      syscallGate = syscallArmPkg != null;

    in
    pkgs.symlinkJoin {
      name = "${lib.getName package}-agent-sandbox";
      paths = [ package ];

      postBuild = ''
        if [ "${if replaceOriginalBinary then "1" else "0"}" = "1" ]; then
          mv $out/bin/${binName} $out/bin/${unsafeAliasPrefix}${binName}
          ln -s ${finalLauncher}/bin/${sandboxedName} $out/bin/${binName}
        fi
        ln -s ${finalLauncher}/bin/${sandboxedName} $out/bin/${sandboxedName}
      '';
    };
}
