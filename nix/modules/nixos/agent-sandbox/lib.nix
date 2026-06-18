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
      absReadwrite = readwriteDirs'.abs ++ readwriteFiles'.abs;

      # sudoGuard must be in sandboxPkgs (add-pkg-deps), not only add-runtime PATH:
      # omp ! shells build PATH from package deps, not the jail launcher exports.
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
    ++ lib.optionals (policyContext && policySocket != null) [
      (agent-sandbox-context-env policySocket)
    ]
    ++ lib.optionals (network != null) [
      (if dynamicFs then c.agent-sandbox-restricted-net-dynamic else agent-sandbox-restricted-net)
    ]
    ++ lib.optionals (network != null && (network.injectProxyEnv or false)) [
      (agent-sandbox-proxy network.proxyUrl)
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
      policyContext ? false,
      network ? null,
      sudoGuard ? null,
      fsArmPkg ? null,
    }:
    let
      binName = if binary != null then binary else lib.baseNameOf (lib.getExe package);

      sandboxedName = "sandboxed-${binName}";

      builtinCombinators = (jail-nix.lib.init pkgs).combinators;

      agentCombinators = import ./combinators.nix { inherit pkgs lib; } builtinCombinators;

      entryPackage =
        if fsArmPkg != null then
          pkgs.writeShellScriptBin binName ''
            exec ${fsArmPkg}/bin/agent-sandbox-fs-arm -- ${lib.getExe package} "$@"
          ''
        else
          package;

      extraPkgs' = extraPkgs ++ lib.optionals (fsArmPkg != null) [ fsArmPkg ];
      dynamicFs = fsArmPkg != null;

      staticAllowRules =
        lib.lists.forEach (readonlyDirs ++ readwriteDirs ++ readonlyFiles ++ readwriteFiles)
          (path: {
            inherit path;
            access = "all";
          });
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
            runtimeReadonlyDirs
            commonPkgs
            devicePaths
            ;
          extraPkgs = extraPkgs';
        }
        ++ lib.optionals (fsArmPkg != null) [
          (builtinCombinators.compose [
            (builtinCombinators.set-env "AGENT_SANDBOX_FS_STATIC_ALLOW" staticAllowJson)
            (builtinCombinators.add-runtime ''
              RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_FS_STATIC_ALLOW ${staticAllowJsonArg})
            '')
          ])
        ]
        ++ lib.optionals (fsArmPkg != null && exposeWorkingDirectory) [
          (builtinCombinators.compose [
            (builtinCombinators.set-env "AGENT_SANDBOX_FS_ALLOW_CWD" "1")
            (builtinCombinators.add-runtime ''
              RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_FS_ALLOW_CWD "1")
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
      entryCmd =
        if fsArmPkg != null then
          "${fsArmPkg}/bin/agent-sandbox-fs-arm -- ${lib.getExe package}"
        else
          lib.getExe package;
      blockScript = lib.concatMapStringsSep "\n" (var: "unset ${var} || true") blockEnvVars;
      namespaceFlags =
        if hasNetwork then
          "--unshare-user --unshare-ipc --unshare-uts --unshare-cgroup"
        else
          "--unshare-user --unshare-ipc --unshare-pid --unshare-net --unshare-uts --unshare-cgroup";
      proxyFlags =
        lib.optionalString (hasNetwork && (network.injectProxyEnv or false))
          "--setenv HTTP_PROXY ${network.proxyUrl} --setenv HTTPS_PROXY ${network.proxyUrl} --setenv ALL_PROXY ${network.proxyUrl} --setenv http_proxy ${network.proxyUrl} --setenv https_proxy ${network.proxyUrl} --setenv NO_PROXY 127.0.0.1,169.254.100.1,localhost,::1";
      dnsScript = lib.optionalString hasNetwork ''
        if [[ -f /etc/agent-sandbox/nsswitch.conf ]]; then
          _real_ns=$(readlink -f /etc/nsswitch.conf 2>/dev/null) || _real_ns=""
          if [[ -n "$_real_ns" ]]; then
            RUNTIME_ARGS+=(--ro-bind /etc/agent-sandbox/nsswitch.conf "$_real_ns")
          fi
        fi
        if [[ -f /etc/agent-sandbox/resolv.conf ]]; then
          _real_resolv=$(readlink -f /etc/resolv.conf 2>/dev/null) || _real_resolv=""
          if [[ -n "$_real_resolv" ]]; then
            RUNTIME_ARGS+=(--ro-bind /etc/agent-sandbox/resolv.conf "$_real_resolv")
          fi
        fi
      '';
      policyScript = lib.optionalString (policyContext && policySocket != null) ''
        _agent_sandbox_home=$(readlink -f "$HOME")
        _agent_sandbox_project_root="$PWD"
        if command -v git >/dev/null 2>&1; then
          _git_root="$(git -C "$PWD" rev-parse --show-toplevel 2>/dev/null)" || true
          [[ -n "$_git_root" ]] && _agent_sandbox_project_root="$_git_root"
        fi
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_POLICY_SOCKET "${policySocket}")
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_CWD "$PWD")
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_HOME "$_agent_sandbox_home")
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_PROJECT_ROOT "$_agent_sandbox_project_root")
      '';
      fsArmScript = lib.optionalString (fsArmPkg != null) ''
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_FS_STATIC_ALLOW ${staticAllowJsonArg})
        ${lib.optionalString exposeWorkingDirectory ''
          RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_FS_ALLOW_CWD "1")
        ''}
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
          if [[ -d /run/opengl-driver/lib ]]; then
            _asbx_ld="/run/opengl-driver/lib"
            if [[ -n "''${LD_LIBRARY_PATH:-}" ]]; then
              case ":$LD_LIBRARY_PATH:" in *":$_asbx_ld:"*) ;; *) _asbx_ld="$_asbx_ld:$LD_LIBRARY_PATH" ;; esac
            fi
            RUNTIME_ARGS+=(--setenv LD_LIBRARY_PATH "$_asbx_ld")
          fi
          ${deviceBindScript}

          ${fsArmScript}

          exec ${pkgs.bubblewrap}/bin/bwrap \
            --bind / / \
            --proc /proc \
            --tmpfs /dev \
            --dev-bind /dev/null /dev/null \
            --dev-bind /dev/zero /dev/zero \
            --dev-bind /dev/random /dev/random \
            --dev-bind /dev/urandom /dev/urandom \
            --dev-bind /dev/full /dev/full \
            --dev-bind /dev/pts /dev/pts \
            --dev-bind /dev/tty /dev/tty \
            --tmpfs /tmp \
            --clearenv \
            --ro-bind ~/.local/share/jail.nix/passwd /etc/passwd \
            --ro-bind ~/.local/share/jail.nix/group /etc/group \
            ${lib.optionalString hasNetwork "--disable-userns"} \
            ${namespaceFlags} \
            --new-session --die-with-parent \
            ${extraBwrapStr} \
            ${proxyFlags} \
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
    in
    pkgs.symlinkJoin {
      name = "${lib.getName package}-agent-sandbox";
      paths = [ package ];
      postBuild = ''
        if [ "${if replaceOriginalBinary then "1" else "0"}" = "1" ]; then
          mv $out/bin/${binName} $out/bin/${unsafeAliasPrefix}${binName}
          ln -s ${launcher}/bin/${sandboxedName} $out/bin/${binName}
        fi
        ln -s ${launcher}/bin/${sandboxedName} $out/bin/${sandboxedName}
      '';
    };
}
