{ lib, pkgs, ... }:

let
  harnessPkg = pkgs.agent-sandbox.harness-integrations;
  sandboxPkg = pkgs.agent-sandbox.agent-sandbox;
  officialPackage =
    {
      aarch64-linux = {
        hash = "sha256-El42Ui1Dx1vXlYR3hGumsc3fLrGc78tX3agL4XQvkX8=";
        architecture = "arm64";
      };

      x86_64-linux = {
        hash = "sha256-NVSwAixs+1EzJvQ/0R9xiDWncIasTXyi/z67ui1Mf0U=";
        architecture = "amd64";
      };
    }
    .${system};
  packagePath = "pool/main/c/chatgpt/chatgpt_${version}_${officialPackage.architecture}.deb";
  runtimeDependencies = with pkgs; [
    alsa-lib
    atk
    at-spi2-atk
    at-spi2-core
    cairo
    cups.lib
    dbus.lib
    expat
    gdk-pixbuf
    glib.out
    graphite2
    gtk3
    libdrm
    libgbm
    libglvnd
    libnotify
    libusb1
    libxkbcommon
    mesa
    nspr
    nss
    openssl.out
    pango.out
    pipewire
    stdenv.cc.cc.lib
    stdenv.cc.cc.libgcc
    qt5.qtbase.out
    qt6.qtbase.out
    systemd
    wayland
    xz.out
    zlib
    zstd.out
    libX11
    libXcomposite
    libXcursor
    libXdamage
    libXext
    libXfixes
    libXi
    libXrandr
    libXScrnSaver
    libXtst
    libxcb
    libxcrypt-legacy
  ];
  system = pkgs.stdenv.hostPlatform.system;
  upstreamDeb = pkgs.fetchurl {
    url = "https://persistent.oaistatic.com/codex-app-prod/linux/deb/${packagePath}";
    hash = officialPackage.hash;
    name = "chatgpt_${version}_${officialPackage.architecture}.deb";
  };
  version = "26.825.51511";
in
pkgs.stdenvNoCC.mkDerivation {
  inherit version;
  inherit runtimeDependencies;
  pname = "codex-desktop";
  src = upstreamDeb;

  nativeBuildInputs = [
    pkgs.autoPatchelfHook
    pkgs.dpkg
    pkgs.makeWrapper
  ];

  buildInputs = runtimeDependencies;

  installPhase = ''
    runHook preInstall
    dpkg-deb -x "$src" "$out"
    cp -a "$out/usr/." "$out/"
    rm -rf "$out/usr" "$out/etc"

    # The app-server transport stays stdio JSON-RPC. A shared socket would
    # erase the logical connection that the adapter observes.
    rm -f "$out/bin/codex" "$out/bin/codex-desktop"
    makeWrapper "$out/lib/chatgpt/resources/codex" "$out/bin/codex-unwrapped" \
      --set-default AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL 1 \
      --set-default AGENT_SANDBOX_CONTEXT_ADAPTER "${harnessPkg}/bin/agent-sandbox-context-adapter" \
      --set-default AGENT_SANDBOX_CHILD "${harnessPkg}/bin/agent-sandbox-child" \
      --set-default AGENT_SANDBOX_PROXY "${sandboxPkg}/bin/agent-sandbox-proxy" \
      --set-default AGENT_SANDBOX_DBUS_PROXY "${sandboxPkg}/bin/agent-sandbox-dbus-proxy" \
      --set-default CODEX_APP_SERVER_TRANSPORT stdio-jsonl \
      --set-default CODEX_APP_SERVER_SHARED_SOCKET 0
    install -Dm0755 /dev/stdin "$out/bin/codex" <<'CODEX'
    #!${pkgs.bash}/bin/bash
    set -euo pipefail
    exec ${harnessPkg}/bin/agent-sandbox-context-adapter -- "@out@/bin/codex-unwrapped" "$@"
    CODEX
    substituteInPlace $out/bin/codex --replace-fail @out@ $out
    makeWrapper "$out/bin/chatgpt" "$out/bin/codex-desktop-unwrapped" \
      --set-default CODEX_CLI_PATH "$out/bin/codex" \
      --set-default AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL 1 \
      --set-default AGENT_SANDBOX_CONTEXT_ADAPTER "${harnessPkg}/bin/agent-sandbox-context-adapter" \
      --set-default AGENT_SANDBOX_CHILD "${harnessPkg}/bin/agent-sandbox-child" \
      --set-default AGENT_SANDBOX_PROXY "${sandboxPkg}/bin/agent-sandbox-proxy" \
      --set-default AGENT_SANDBOX_DBUS_PROXY "${sandboxPkg}/bin/agent-sandbox-dbus-proxy" \
      --set-default CODEX_APP_SERVER_TRANSPORT stdio-jsonl \
      --set-default CODEX_APP_SERVER_SHARED_SOCKET 0
    install -Dm0755 /dev/stdin "$out/bin/codex-desktop" <<'DESKTOP'
    #!${pkgs.bash}/bin/bash
    set -euo pipefail
    exec ${harnessPkg}/bin/agent-sandbox-context-adapter -- "@out@/bin/codex-desktop-unwrapped" "$@"
    DESKTOP
    substituteInPlace $out/bin/codex-desktop --replace-fail @out@ $out

    install -Dm0644 /dev/stdin "$out/share/agent-sandbox/codex-desktop.json" <<EOF
    {
      "desktopVersion": "${version}",
      "desktopPackage": "${packagePath}",
      "bundledCliVersion": "0.151.0-alpha.7.2",
      "bundledCliSha256": "d32a5e9f6201f8e20849ff4b52e559920b43c7937dce8051bd9fb3d4a0bef3f1",
      "appServerTransport": "stdio-jsonl",
      "sharedSocket": false,
      "asarPatch": null
    }
    EOF
    runHook postInstall
  '';

  autoPatchelfIgnoreMissingDeps = [ "libc.musl-x86_64.so.1" ];

  passthru = {
    desktopPackagingSourceCommit = "241435e57b27da16e1a4381dabeb9c63876dfab2";
    desktopSourceCommit = "e021215ca0743dd1403bb4c76765e4316d9eea4a";

    desktopSourceTarball = pkgs.fetchurl {
      url = "https://github.com/ilysenko/codex-desktop-linux/archive/e021215ca0743dd1403bb4c76765e4316d9eea4a.tar.gz";
      hash = "sha256-aTiYiHAT+K+fcSZAA615m+CRBpoVjz0re7hAmC2dH0w=";
    };

    runtimeSourceCommit = "f70e26c29ccb731e22d1104de550b1b9594d7070";

    runtimeSourceTarball = pkgs.fetchurl {
      url = "https://github.com/openai/codex/archive/f70e26c29ccb731e22d1104de550b1b9594d7070.tar.gz";
      hash = "sha256-lEhEB+oXCfTvA/slM70yTTiouapWitstyCHHfVmInQw=";
    };

    runtimeSurveyCommit = "94cbbddafc1776d5e377bca1b05932c697e82238";
  };

  meta = {
    description = "Codex Desktop with a task-local context adapter seam";
    homepage = "https://github.com/ilysenko/codex-desktop-linux";
    license = lib.licenses.mit;

    platforms = [
      "x86_64-linux"
      "aarch64-linux"
    ];

    mainProgram = "codex-desktop";
  };
}
