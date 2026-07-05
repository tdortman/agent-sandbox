# Additional jail.nix combinators for agent-sandbox (home mounts, restricted net).
{ pkgs, lib, ... }:
builtin:
let
  inherit (builtin)
    add-path
    add-pkg-deps
    add-runtime
    compose
    fwd-env
    include-once
    ro-bind
    runtime-deep-ro-bind
    set-env
    share-ns
    time-zone
    try-readonly
    unsafe-add-raw-args
    ;

  # Like jail.nix `base`, but bind host /dev/pts instead of `--dev /dev` (which tries to
  # recreate the caller's pts node and fails with --disable-userns).
  agent-sandbox-base = compose [
    (unsafe-add-raw-args "--proc /proc")
    (unsafe-add-raw-args "--tmpfs /dev")
    (unsafe-add-raw-args "--dev-bind /dev/null /dev/null")
    (unsafe-add-raw-args "--dev-bind /dev/zero /dev/zero")
    (unsafe-add-raw-args "--dev-bind /dev/random /dev/random")
    (unsafe-add-raw-args "--dev-bind /dev/urandom /dev/urandom")
    (unsafe-add-raw-args "--dev-bind /dev/full /dev/full")
    (unsafe-add-raw-args "--dev-bind /dev/pts /dev/pts")
    (unsafe-add-raw-args "--dev-bind /dev/tty /dev/tty")
    (unsafe-add-raw-args "--bind /tmp /tmp")
    (unsafe-add-raw-args "--tmpfs ~")
    (ro-bind "${pkgs.bash}/bin/sh" "/bin/sh")
    (add-path "/bin")
    (add-pkg-deps [
      pkgs.coreutils
      pkgs.bash
    ])
    (unsafe-add-raw-args "--clearenv")
    (fwd-env "LANG")
    (fwd-env "HOME")
    (fwd-env "TERM")
  ];

  # Base combinator for dynamic filesystem-approval mode.
  # Exposes the full host filesystem via --bind / / so that fanotify (fsmon)
  # can gate individual opens instead of relying on static bwrap mounts.
  # Sandbox-private /proc and /dev still overlay the host root. /tmp is the
  # host tree so agents can share scratch files with the outside world.
  agent-sandbox-dynamic-base = compose [
    (unsafe-add-raw-args "--bind / /")
    (unsafe-add-raw-args "--proc /proc")
    (unsafe-add-raw-args "--tmpfs /dev")
    (unsafe-add-raw-args "--dev-bind /dev/null /dev/null")
    (unsafe-add-raw-args "--dev-bind /dev/zero /dev/zero")
    (unsafe-add-raw-args "--dev-bind /dev/random /dev/random")
    (unsafe-add-raw-args "--dev-bind /dev/urandom /dev/urandom")
    (unsafe-add-raw-args "--dev-bind /dev/full /dev/full")
    (unsafe-add-raw-args "--dev-bind /dev/pts /dev/pts")
    (unsafe-add-raw-args "--dev-bind /dev/tty /dev/tty")
    (add-pkg-deps [
      pkgs.coreutils
      pkgs.bash
    ])
    (unsafe-add-raw-args "--clearenv")
    (fwd-env "LANG")
    (fwd-env "HOME")
    (fwd-env "TERM")
  ];

  inheritShellEnvRuntime = ''
    declare -A _asbx_bound=()
    _asbx_wants_store=0
    _asbx_pwd_root=""
    _asbx_home_root=""
    if [[ -n "$PWD" ]] && [[ -d "$PWD" ]]; then
      _asbx_pwd_root=$(readlink -f "$PWD" 2>/dev/null) || _asbx_pwd_root=""
    fi
    if [[ -n "$HOME" ]] && [[ -d "$HOME" ]]; then
      _asbx_home_root=$(readlink -f "$HOME" 2>/dev/null) || _asbx_home_root=""
    fi
    _asbx_under_pwd() {
      local p="$1"
      [[ -n "$_asbx_pwd_root" ]] || return 1
      [[ "$p" == "$_asbx_pwd_root" || "$p" == "$_asbx_pwd_root"/* ]]
    }
    _asbx_under_home() {
      local p="$1"
      [[ -n "$_asbx_home_root" ]] || return 1
      [[ "$p" == "$_asbx_home_root" || "$p" == "$_asbx_home_root"/* ]]
    }
    _asbx_is_jail_tmpfs() {
      # Host /tmp is bind-mounted; skip per-path ro-binds for entries under it.
      local p="$1"
      [[ "$p" == "/tmp" || "$p" == /tmp/* ]] && return 0
      [[ "$p" == "/var/tmp" || "$p" == /var/tmp/* ]] && return 0
      return 1
    }
    _asbx_note_path_entry() {
      local dir="$1"
      if [[ -z "$dir" ]] || [[ ! -e "$dir" ]]; then
        return 0
      fi
      local _asbx_real
      if ! _asbx_real=$(readlink -f "$dir" 2>/dev/null); then
        return 0
      fi
      if _asbx_is_jail_tmpfs "$_asbx_real"; then
        return 0
      fi
      if _asbx_under_pwd "$_asbx_real"; then
        return 0
      fi
      # Under $HOME only explicit home-*-mounts apply (~ is tmpfs otherwise).
      if _asbx_under_home "$_asbx_real"; then
        return 0
      fi
      if [[ "$_asbx_real" == /nix/store/* ]]; then
        _asbx_wants_store=1
        return 0
      fi
      if [[ -n "''${_asbx_bound[$_asbx_real]+set}" ]]; then
        return 0
      fi
      _asbx_bound["$_asbx_real"]=1
      RUNTIME_ARGS+=(--ro-bind "$_asbx_real" "$_asbx_real")
    }
    _asbx_scan_env_value() {
      local val="$1"
      [[ "$val" == /* ]] || return 0
      [[ "$val" == *://* ]] && return 0
      local _asbx_part
      if [[ "$val" == *:* ]]; then
        IFS=: read -ra _asbx_parts <<< "$val"
        for _asbx_part in "''${_asbx_parts[@]}"; do
          [[ "$_asbx_part" == /* ]] && _asbx_note_path_entry "$_asbx_part"
        done
      else
        _asbx_note_path_entry "$val"
      fi
    }
    while IFS= read -r -d $'\0' _asbx_line; do
      case "$_asbx_line" in
        *=*) ;;
        *) continue ;;
      esac
      _asbx_name="''${_asbx_line%%=*}"
      _asbx_val="''${_asbx_line#*=}"
      case "$_asbx_name" in
        *[!A-Za-z0-9_]*|"") continue ;;
        TMPDIR|TEMP|TMP) continue ;;
      esac
      _asbx_scan_env_value "$_asbx_val"
      [[ "$_asbx_name" == "PATH" ]] && continue
      RUNTIME_ARGS+=(--setenv "$_asbx_name" "$_asbx_val")
    done < <(env -0)
    if (( _asbx_wants_store )); then
      RUNTIME_ARGS+=(--ro-bind /nix/store /nix/store)
    fi
    # mount-cwd is earlier in bwrap argv; re-bind last so env path scans cannot override rw.
    if [[ -n "$_asbx_pwd_root" ]]; then
      RUNTIME_ARGS+=(--bind "$_asbx_pwd_root" "$_asbx_pwd_root")
    fi
  '';

  # Dynamic-FS variant: forward env vars via --setenv but skip all --ro-bind
  # mounts.  The entire host filesystem is already visible via --bind / /,
  # so scanning env vars for paths and rebinding them is both redundant and
  # broken (bwrap cannot mkdir through symlinks on a root-bound tree).
  inheritShellEnvRuntimeDynamic = ''
    while IFS= read -r -d $'\0' _asbx_line; do
      case "$_asbx_line" in
        *=*) ;;
        *) continue ;;
      esac
      _asbx_name="''${_asbx_line%%=*}"
      _asbx_val="''${_asbx_line#*=}"
      case "$_asbx_name" in
        *[!A-Za-z0-9_]*|"") continue ;;
        TMPDIR|TEMP|TMP) continue ;;
        PATH) continue ;;
      esac
      RUNTIME_ARGS+=(--setenv "$_asbx_name" "$_asbx_val")
    done < <(env -0)
  '';

  # Shared bash: mount path at $hostPath, follow symlinks (chezmoi → dotfiles),
  # exposing each resolved target at its real path (read-only).
  mountHomePathFn = ''
    mount_home_path() {
      local hostPath="$1"
      local bindFlag="$2"
      [[ -e "$hostPath" || -L "$hostPath" ]] || return 0
      bind_canon_target() {
        local canon="$1"
        [[ -e "$canon" ]] || return 0
        [[ -n "''${_agent_sandbox_canon[$canon]+set}" ]] && return 0
        _agent_sandbox_canon["$canon"]=1
        RUNTIME_ARGS+=(--ro-bind "$canon" "$canon")
      }
      if [[ -L "$hostPath" ]]; then
        local canon
        canon=$(readlink -f "$hostPath")
        bind_canon_target "$canon"
        RUNTIME_ARGS+=(--symlink "$(readlink "$hostPath")" "$hostPath")
        return 0
      fi
      if [[ -d "$hostPath" ]]; then
        RUNTIME_ARGS+=("$bindFlag" "$hostPath" "$hostPath")
        local link canon
        while IFS= read -r -d $'\0' link; do
          canon=$(readlink -f "$link" 2>/dev/null) || continue
          [[ -e "$canon" ]] || continue
          [[ "$canon" == "$hostPath"/* ]] && continue
          bind_canon_target "$canon"
        done < <(find "$hostPath" -type l -print0 2>/dev/null)
      else
        RUNTIME_ARGS+=("$bindFlag" "$hostPath" "$hostPath")
      fi
    }
  '';
in
{
  inherit agent-sandbox-base agent-sandbox-dynamic-base;

  home-readonly-mounts =
    rels:
    if rels == [ ] then
      (s: s)
    else
      add-runtime ''
        realHome=$(readlink -f "$HOME")
        declare -A _agent_sandbox_canon=()
        ${mountHomePathFn}
        ${lib.concatMapStringsSep "\n" (rel: ''
          mount_home_path "$realHome/${rel}" --ro-bind
        '') rels}
      '';

  home-readwrite-mounts =
    rels:
    if rels == [ ] then
      (s: s)
    else
      add-runtime ''
        realHome=$(readlink -f "$HOME")
        declare -A _agent_sandbox_canon=()
        ${mountHomePathFn}
        ${lib.concatMapStringsSep "\n" (rel: ''
          mount_home_path "$realHome/${rel}" --bind
        '') rels}
      '';

  block-env-vars =
    vars:
    if vars == [ ] then
      (s: s)
    else
      add-runtime ''
        ${lib.concatMapStringsSep "\n" (var: "unset ${var} || true") vars}
      '';

  # Inherit the invoking shell env (opt-out: block-env-vars unsets secrets before this runs).
  # fwd-env PATH must precede add-pkg-deps so sandbox bins are prepended, not replaced.
  inherit-shell-env = include-once "agent-sandbox-inherit-shell-env" (compose [
    (fwd-env "PATH")
    (add-runtime inheritShellEnvRuntime)
  ]);

  inherit-shell-env-dynamic = include-once "agent-sandbox-inherit-shell-env-dynamic" (compose [
    (fwd-env "PATH")
    (add-runtime inheritShellEnvRuntimeDynamic)
  ]);

  agent-sandbox-context-env =
    { sandboxPolicySocket, ... }:
    compose [
      (set-env "AGENT_SANDBOX_POLICY_SOCKET" sandboxPolicySocket)
      (add-runtime ''
        # jail.nix base uses --clearenv; only --setenv survives into the jail.
        # policyd and enforcement daemons read these from /proc/<pid>/environ.
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
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_POLICY_SOCKET "''${sandboxPolicySocket}")
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_CWD "$_agent_sandbox_cwd")
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_HOME "$_agent_sandbox_home")
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_PROJECT_ROOT "$_agent_sandbox_project_root")
        RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_SESSION_ID "$_agent_sandbox_session_id")
        RUNTIME_ARGS+=(--ro-bind-try "''${sandboxPolicySocket}" "''${sandboxPolicySocket}")
      '')
      (lib.id sandboxPolicySocket)
    ];

  # GPU device nodes need --dev-bind (rw). try-readonly breaks NVML/CUDA ioctls.
  try-dev-bind =
    path:
    add-runtime ''
      if [[ -e "${path}" ]]; then
        RUNTIME_ARGS+=(--dev-bind "${path}" "${path}")
      fi
    '';

  # Bind all host NVIDIA nodes (including nvidia-fs* when nvidia-fs is enabled).
  # Must run after inherit-shell-env so LD_LIBRARY_PATH can prefer /run/opengl-driver.
  agent-sandbox-nvidia-gpu = add-runtime ''
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
        case ":$LD_LIBRARY_PATH:" in
          *":$_asbx_ld:"*) ;;
          *) _asbx_ld="$_asbx_ld:$LD_LIBRARY_PATH" ;;
        esac
      fi
      RUNTIME_ARGS+=(--setenv LD_LIBRARY_PATH "$_asbx_ld")
    fi
  '';

  # Sudo guard combinator. The guard binary is exposed on PATH so that
  # plain `sudo` inside the sandbox routes through it. No bind-mount at
  # /run/wrappers/bin/sudo — the host's sudo wrapper is left untouched.
  agent-sandbox-sudo-guard =
    sudoPkg:
    compose [
      (add-runtime ''
        export PATH="${sudoPkg}/bin:''${PATH:-/dev/null}"
      '')
    ];

  agent-sandbox-restricted-net = include-once "agent-sandbox-restricted-net" (compose [
    (share-ns "net")
    (runtime-deep-ro-bind "/etc/hosts")
    (add-runtime ''
      if [[ -f /etc/agent-sandbox/nsswitch.conf ]]; then
        RUNTIME_ARGS+=(--ro-bind /etc/agent-sandbox/nsswitch.conf /etc/nsswitch.conf)
      else
        RUNTIME_ARGS+=(--ro-bind /etc/nsswitch.conf /etc/nsswitch.conf)
      fi
    '')
    (runtime-deep-ro-bind "/etc/ssl")
    (add-runtime ''
      # Points at the veth gateway. agent-sandbox-dns-forwarder sends to host systemd-resolved.
      if [[ -f /etc/agent-sandbox/resolv.conf ]]; then
        RUNTIME_ARGS+=(--ro-bind /etc/agent-sandbox/resolv.conf /etc/resolv.conf)
      fi
    '')
    (add-runtime ''
      if [[ -d /run/nscd ]]; then
        RUNTIME_ARGS+=(--tmpfs /run/nscd)
      fi
    '')
    (try-readonly "/etc/static/ssl")
    (try-readonly "/run/opengl-driver")
    (try-readonly "/run/opengl-driver-32")
    (try-readonly "/run/current-system")
    (try-readonly "/run/wrappers")
    (try-readonly "/run/agent-sandbox")
    (try-readonly "/run/netns")
    (unsafe-add-raw-args "--disable-userns")
  ]);

  # Dynamic-FS variant: skip all redundant bind mounts since --bind / / exposes
  # everything.  Keep only namespace sharing, DNS file replacements, and userns
  # disable.  The try-readonly calls fail on symlinks under a root-bound tree.
  agent-sandbox-restricted-net-dynamic = include-once "agent-sandbox-restricted-net" (compose [
    time-zone
    (share-ns "pid")
    (share-ns "net")
    (add-runtime ''
      if [[ -f /etc/agent-sandbox/nsswitch.conf ]]; then
        RUNTIME_ARGS+=(--ro-bind /etc/agent-sandbox/nsswitch.conf /etc/nsswitch.conf)
      fi
    '')
    (add-runtime ''
      if [[ -f /etc/agent-sandbox/resolv.conf ]]; then
        RUNTIME_ARGS+=(--ro-bind /etc/agent-sandbox/resolv.conf /etc/resolv.conf)
      fi
    '')
    (add-runtime ''
      if [[ -d /run/nscd ]]; then
        RUNTIME_ARGS+=(--tmpfs /run/nscd)
      fi
    '')
    (unsafe-add-raw-args "--disable-userns")
  ]);
}
