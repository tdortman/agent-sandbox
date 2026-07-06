{
  lib,
  inputs,
  pkg-config,
  cmake,
  makeWrapper,
  pkgs,
  ...
}:
let
  rust = (import "${inputs.self}/nix/lib/rust-toolchain.nix") { inherit pkgs; };

  qtDialog = pkgs.stdenv.mkDerivation {
    name = "agent-sandbox-qt-dialog";
    src = ./qt-helper;
    nativeBuildInputs = [
      cmake
      pkgs.qt6.wrapQtAppsHook
    ];
    buildInputs = [ pkgs.qt6.qtbase ];
  };
  src = inputs.self;
  workspacePackage = (fromTOML (builtins.readFile "${src}/Cargo.toml")).workspace.package;
in
rust.rustPlatform.buildRustPackage {
  pname = "agent-sandbox";
  inherit (workspacePackage) version;
  inherit src;

  # seccompiler is a git dep (pinned to the commit that adds
  # SECCOMP_RET_USER_NOTIF). Nix's cargoLock importer cannot infer the
  # hash for git-sourced crates, so we supply it explicitly. To refresh
  # after bumping the seccompiler rev, run `nix flake prefetch
  # git+https://github.com/rust-vmm/seccompiler.git?rev=<NEW_REV>` and
  # paste the SRI hash below.
  cargoLock = {
    lockFile = "${src}/Cargo.lock";
    outputHashes."seccompiler-0.5.0" = "sha256-k1TNr0GA8GeJYo1RvB/cfuvVg+tN4G7yypkVkhSq+h8=";
  };

  nativeBuildInputs = [
    pkg-config
    makeWrapper
  ];

  doCheck = true;
  useNextest = true;

  postInstall = ''
    # Copy the Qt dialog helper into the package.
    cp ${qtDialog}/bin/agent-sandbox-qt-dialog $out/bin/

    # Wrap the UI: expose the packaged Qt6 helper as the default
    # `qt-dialog` backend. Zenity remains module-selected, not bundled here.
    wrapProgram $out/bin/agent-sandbox-ui \
      --prefix PATH : $out/bin \
      --set-default AGENT_SANDBOX_QT_DIALOG $out/bin/agent-sandbox-qt-dialog

    # Install zsh completion.
    install -Dm644 ${./_agent-sandbox-approve} $out/share/zsh/site-functions/_agent-sandbox-approve
  '';

  meta = with lib; {
    description = "Policy daemon, NFQUEUE enforcer, DNS cache, CLIs, netns enter helper, and Qt-wrapped UI";
    license = licenses.mit;
  };
}
