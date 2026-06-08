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
    in
    with c;
    [
      (block-env-vars blockEnvVars)
      inherit-shell-env
      (add-pkg-deps sandboxPkgs)
    ]
    ++ lib.optionals exposeWorkingDirectory [ mount-cwd ]
    ++ map try-readonly (lib.unique (runtimeReadonlyDirs ++ absReadonly))
    ++ map try-readwrite absReadwrite
    ++ [
      (home-readonly-mounts homeReadonly)
      (home-readwrite-mounts homeReadwrite)
    ]
    ++ lib.optionals (policySocket != null && network != null) [
      (agent-sandbox-context-env policySocket)
    ]
    ++ lib.optionals (network != null) [
      agent-sandbox-restricted-net
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
      network ? null,
      sudoGuard ? null,
    }:
    let
      binName = if binary != null then binary else lib.baseNameOf (lib.getExe package);

      sandboxedName = "sandboxed-${binName}";

      builtinCombinators = (jail-nix.lib.init pkgs).combinators;

      agentCombinators = import ./combinators.nix { inherit pkgs lib; } builtinCombinators;

      jailFn = jail-nix.lib.extend {
        inherit pkgs;
        additionalCombinators = _: agentCombinators;
        basePermissions =
          c: with c; [
            agent-sandbox-base
            bind-nix-store-runtime-closure
            fake-passwd
          ];
      };

      permissions = buildPermissions (builtinCombinators // agentCombinators) {
        inherit
          package
          readonlyDirs
          readwriteDirs
          readonlyFiles
          readwriteFiles
          extraPkgs
          runtimeReadonlyDirs
          devicePaths
          blockEnvVars
          exposeWorkingDirectory
          extraBwrapArgs
          policySocket
          network
          sudoGuard
          ;
        inherit commonPkgs;
      };

      jailedDrv = jailFn sandboxedName package permissions;

      launcher =
        if network != null then
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
