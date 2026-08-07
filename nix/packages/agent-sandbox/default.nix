{
  lib,
  cmake,
  inputs,
  makeWrapper,
  pkgs,
  ...
}:
let
  qtDialog = pkgs.stdenv.mkDerivation {
    src = ./qt-helper;

    nativeBuildInputs = [
      cmake
      pkgs.qt6.wrapQtAppsHook
    ];

    buildInputs = [ pkgs.qt6.qtbase ];
    name = "agent-sandbox-qt-dialog";
  };
  rust = (import "${inputs.self}/nix/lib/rust-toolchain.nix") { inherit pkgs; };
  src = inputs.self;
  workspacePackage = (fromTOML (builtins.readFile "${src}/Cargo.toml")).workspace.package;

in
rust.rustPlatform.buildRustPackage {
  inherit (workspacePackage) version;
  inherit src;
  pname = "agent-sandbox";

  nativeBuildInputs = [
    cmake
    makeWrapper
    pkgs.gitMinimal
    rust.rustPlatform.bindgenHook
  ];

  cargoLock = {
    lockFile = "${src}/Cargo.lock";

    outputHashes = {
      "h3-quinn-0.0.10" = "sha256-9s9/OxQm3TTWpcNYK+BUKahro9acdbAqYRBZdnEp1O4=";
      "seccompiler-0.5.0" = "sha256-k1TNr0GA8GeJYo1RvB/cfuvVg+tN4G7yypkVkhSq+h8=";
    };
  };

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
