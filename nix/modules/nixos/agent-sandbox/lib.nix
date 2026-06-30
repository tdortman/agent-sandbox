{
  lib,
  jail-nix,
}:
let
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

  defaultRuntimeReadonlyDirs = [
    "/run/current-system"
    "/run/wrappers"
    "/run/opengl-driver"
    "/run/opengl-driver-32"
  ];

  # Extra device nodes (agent-sandbox-nvidia-gpu binds the standard NVIDIA set).
  defaultDevicePaths = [ ];

  isHomeMountPath = path: path == "~" || lib.hasPrefix "~/" path;

  isHostMountPath = path: lib.hasPrefix "/" path;

  homeMountRel = path: if path == "~" then "" else lib.removePrefix "~/" path;

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
        home = map homeMountRel (lib.filter isHomeMountPath paths);
        abs = lib.filter isHostMountPath paths;
      };

  buildPermissions =
    c:
    {
      dynamicFs ? false,
      readonlyDirs ? [ ],
      readwriteDirs ? [ ],
      readonlyFiles ? [ ],
      readwriteFiles ? [ ],
      extraPkgs ? [ ],
      runtimeReadonlyDirs ? defaultRuntimeReadonlyDirs,
      devicePaths ? defaultDevicePaths,
      commonPkgs ? defaultCommonPkgs,
      blockEnvVars ? defaultBlockEnvVars,
      exposeWorkingDirectory ? true,
      extraBwrapArgs ? [ ],
      policySocket ? null,
      sandboxPolicySocket ? null,
      policyContext ? false,
      network ? null,
      sudoGuard ? null,
      ...
    }@cfg:
    let
      readonlyDirs' = splitMountPaths readonlyDirs;
      readwriteDirs' = splitMountPaths readwriteDirs;
      readonlyFiles' = splitMountPaths readonlyFiles;
      readwriteFiles' = splitMountPaths readwriteFiles;

      homeReadonly = readonlyDirs'.home ++ readonlyFiles'.home;
      homeReadwrite = readwriteDirs'.home ++ readwriteFiles'.home;

      absReadonly = readonlyDirs'.abs ++ readonlyFiles'.abs;
      absReadwrite = readonlyDirs'.abs ++ readwriteFiles'.abs;
      # sudoGuard must be in sandboxPkgs (add-pkg-deps), not only add-runtime PATH:
      # policyd-built shells build PATH from package deps, not the jail launcher exports.
      sandboxPkgs = lib.unique (
        [ cfg.package ] ++ commonPkgs ++ extraPkgs ++ lib.optionals (sudoGuard != null) [ sudoGuard ]
      );

      # In dynamic-FS mode the full host filesystem is visible via --bind / /.
      # All bind-mount combinators are redundant and broken (bwrap cannot mkdir
      # through symlinks on a root-bound tree), so we skip them entirely.
      inheritShell = if dynamicFs then c.inherit-shell-env-dynamic else c.inherit-shell-env;
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
    ++ lib.optionals (policyContext && policySocket != null && sandboxPolicySocket != null) [
      (agent-sandbox-context-env { inherit policySocket sandboxPolicySocket; })
    ]
    ++ lib.optionals (network != null) [
      (if dynamicFs then c.agent-sandbox-restricted-net-dynamic else agent-sandbox-restricted-net)
    ]
    ++ lib.optionals (sudoGuard != null) [
      (agent-sandbox-sudo-guard sudoGuard)
    ]
    ++ map unsafe-add-raw-args extraBwrapArgs
    ++ [
      agent-sandbox-nvidia-gpu
    ]
    ++ map try-dev-bind devicePaths;

in
rec {
  inherit
    defaultCommonPkgs
    defaultBlockEnvVars
    defaultRuntimeReadonlyDirs
    defaultDevicePaths
    ;

  mkWrapPackage =
    pkgs:
    {
      package,
      binary ? null,
      readonlyDirs ? [ ],
      readwriteDirs ? [ ],
      readonlyFiles ? [ ],
      readwriteFiles ? [ ],
      extraPkgs ? [ ],
      runtimeReadonlyDirs ? defaultRuntimeReadonlyDirs,
      devicePaths ? defaultDevicePaths,
      commonPkgs ? defaultCommonPkgs pkgs,
      blockEnvVars ? defaultBlockEnvVars,
      exposeWorkingDirectory ? true,
      extraBwrapArgs ? [ ],
      replaceOriginalBinary ? true,
      unsafeAliasPrefix ? "unsafe-",
      policySocket ? null,
      sandboxPolicySocket ? null,
      policyContext ? false,
      network ? null,
      sudoGuard ? null,
      fsArmPkg ? null,
      syscallArmPkg ? null,
      resourceGate ? false,
    }:
    let
      binName = if binary != null then binary else lib.baseNameOf (lib.getExe package);

      sandboxedName = "sandboxed-${binName}";

      builtinCombinators = (jail-nix.lib.init pkgs).combinators;

      agentCombinators = import ./combinators.nix { inherit pkgs lib; } builtinCombinators;

      # Syscall gate: when wired, prepend `agent-sandbox-syscall-arm --` to
      # the entry chain. The arm helper installs a seccomp filter inside the
      # sandbox, then execs its argv tail. The chain is composable with the
      # fs-arm helper so dynamic-FS and syscall-gate can both be active.
      syscallGate = syscallArmPkg != null;
      dynamicFs = fsArmPkg != null;

      entryBase =
        if fsArmPkg != null then
          "${fsArmPkg}/bin/agent-sandbox-fs-arm -- ${lib.getExe package}"
        else
          lib.getExe package;
      syscallArmPrefix = if syscallGate then "${syscallArmPkg}/bin/agent-sandbox-syscall-arm --" else "";

      entryPackage =
        if syscallGate || fsArmPkg != null then
          pkgs.writeShellScriptBin binName ''
            exec ${syscallArmPrefix} ${entryBase} "$@"
          ''
        else
          package;

      extraPkgs' =
        extraPkgs
        ++ lib.optionals (fsArmPkg != null) [ fsArmPkg ]
        ++ lib.optionals (syscallArmPkg != null) [ syscallArmPkg ];

      staticAllowRules = [
        {
          path = "/nix/store";
          access = "all";
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
      staticAllowJson = builtins.toJSON staticAllowRules;
      staticAllowJsonArg = lib.escapeShellArg staticAllowJson;

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

      permissions =
        buildPermissions (builtinCombinators // agentCombinators) {
          inherit
            dynamicFs
            package
            readonlyDirs
            readwriteDirs
            readonlyFiles
            readwriteFiles
            blockEnvVars
            exposeWorkingDirectory
            extraBwrapArgs
            policySocket
            policyContext
            network
            sudoGuard
            fsArmPkg
            syscallArmPkg
            runtimeReadonlyDirs
            commonPkgs
            devicePaths
            ;
        }
        ++ lib.optionals (fsArmPkg != null) [
          (builtinCombinators.compose [
            (builtinCombinators.set-env "AGENT_SANDBOX_FS_STATIC_ALLOW" staticAllowJson)
            (builtinCombinators.add-runtime ''
              RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_FS_STATIC_ALLOW ${staticAllowJsonArg})
            '')
          ])
        ];

      jailedDrv = jailFn sandboxedName entryPackage permissions;

      # ---- Dynamic-FS direct wrapper (bypasses jail-nix entirely) ----
      # When dynamic FS approval is active, --bind / / exposes the full host
      # filesystem.  Every jail-nix bind-mount combinator is both redundant and
      # broken (bwrap cannot mkdir through symlinks on a root-bound tree).
      # Generate the wrapper directly to guarantee zero unexpected bind mounts.
      hasNetwork = network != null;
      sandboxPkgsList = lib.unique (
        [ package ] ++ commonPkgs ++ extraPkgs' ++ lib.optionals (sudoGuard != null) [ sudoGuard ]
      );
      sandboxPathStr = lib.makeBinPath sandboxPkgsList;
      entryCmd = "${syscallArmPrefix} ${entryBase}";
      blockScript = lib.concatMapStringsSep "\n" (var: "unset ${var} || true") blockEnvVars;
      namespaceFlags =
        if hasNetwork then
          "--unshare-user --unshare-ipc --unshare-uts --unshare-cgroup"
        else
          "--unshare-user --unshare-ipc --unshare-pid --unshare-net --unshare-uts --unshare-cgroup";
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

      # Rebind explicit narrow /run/* mounts configured by the package
      # definition. Skip the broad /run path so the host's runtime sockets
      # stay hidden by the surrounding tmpfs.
      runReadonlyBindScript = lib.concatMapStringsSep "\n" (
        path:
        if path == "/run" then
          ""
        else
          ''
            if [[ -e "${path}" ]]; then
              RUNTIME_ARGS+=(--ro-bind "${path}" "${path}")
            fi
          ''
      ) (lib.filter (p: lib.hasPrefix "/run/" p) (lib.unique (readonlyDirs ++ readonlyFiles)));

      runReadwriteBindScript = lib.concatMapStringsSep "\n" (
        path:
        if path == "/run" then
          ""
        else
          ''
            if [[ -e "${path}" ]]; then
              RUNTIME_ARGS+=(--bind "${path}" "${path}")
            fi
          ''
      ) (lib.filter (p: lib.hasPrefix "/run/" p) (lib.unique (readwriteDirs ++ readwriteFiles)));

      runMaskScript =
        if resourceGate then
          ''
            if [[ -d /run/agent-sandbox ]]; then
              RUNTIME_ARGS+=(--tmpfs /run/agent-sandbox)
            fi
            # In resource-gate mode /run comes from --bind / /, so safe
            # runtime paths are already visible. Only /run/agent-sandbox
            # needs masking (above) to hide the host control socket.
          ''
        else
          ''
            RUNTIME_ARGS+=(--tmpfs /run)
            for _asbx_safe_runtime in /run/current-system /run/wrappers /run/opengl-driver /run/opengl-driver-32 /run/netns; do
              if [[ -e "$_asbx_safe_runtime" ]]; then
                RUNTIME_ARGS+=(--ro-bind "$_asbx_safe_runtime" "$_asbx_safe_runtime")
              fi
            done
            RUNTIME_ARGS+=(--dir /run/agent-sandbox)
          '';

      policyScript =
        lib.optionalString (policyContext && policySocket != null && sandboxPolicySocket != null)
          ''
            # Reuse outer context if already set (e.g. by agent-sandbox-open-ui-fd).
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
            RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_POLICY_SOCKET ${lib.escapeShellArg sandboxPolicySocket})
            RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_CWD "$_agent_sandbox_cwd")
            RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_HOME "$_agent_sandbox_home")
            RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_PROJECT_ROOT "$_agent_sandbox_project_root")
            RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_SESSION_ID "$_agent_sandbox_session_id")

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
      fsArmScript = lib.optionalString (fsArmPkg != null) ''
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_FS_STATIC_ALLOW ${staticAllowJsonArg})
      '';
      deviceBindScript = lib.concatMapStringsSep "\n" (path: ''
        if [[ -e "${path}" ]]; then
          RUNTIME_ARGS+=(--dev-bind "${path}" "${path}")
        fi
      '') devicePaths;
      extraBwrapStr = lib.concatStringsSep " " extraBwrapArgs;

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
          ${dnsScript}

          ${lib.optionalString (!resourceGate) ''
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
              case ":$LD_LIBRARY_PATH:" in *":$_asbx_ld:"*) ;; *) _asbx_ld="$_asbx_ld:$LD_LIBRARY_PATH" ;; esac
            fi
            RUNTIME_ARGS+=(--setenv LD_LIBRARY_PATH "$_asbx_ld")
          fi
          ${lib.optionalString (!resourceGate) deviceBindScript}

          ${fsArmScript}

          exec ${pkgs.bubblewrap}/bin/bwrap \
            --bind / / \
            --proc /proc \
            --dev-bind /dev /dev \
            --tmpfs /tmp \
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
        '';
      };

      dynamicLauncher =
        if hasNetwork then
          pkgs.writeShellApplication {
            name = sandboxedName;
            text = ''
              set -euo pipefail
              exec ${lib.escapeShellArg network.netnsEnter} ${lib.escapeShellArg network.netnsName} \
                ${lib.getExe dynamicInner} "$@"
            '';
          }
        else
          dynamicInner;

      launcher =
        if dynamicFs then
          dynamicLauncher
        else if network != null then
          pkgs.writeShellApplication {
            name = sandboxedName;
            text = ''
              set -euo pipefail
              exec ${lib.escapeShellArg network.netnsEnter} ${lib.escapeShellArg network.netnsName} \
                ${lib.getExe jailedDrv} "$@"
            '';
          }
        else
          jailedDrv;
      finalLauncher = launcher;

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
