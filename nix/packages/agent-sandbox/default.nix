{
  lib,
  inputs,
  pkg-config,
  cmake,
  rustPlatform,
  makeWrapper,
  pkgs,
  ...
}:
let
  qtDialog = pkgs.stdenv.mkDerivation {
    name = "agent-sandbox-qt-dialog";
    src = ./qt-helper;
    nativeBuildInputs = [
      cmake
      pkgs.qt6.wrapQtAppsHook
    ];
    buildInputs = [ pkgs.qt6.qtbase ];
  };
in
rustPlatform.buildRustPackage (
  let
    src = inputs.self;
    workspacePackage = (fromTOML (builtins.readFile "${src}/Cargo.toml")).workspace.package;
  in
  {
    pname = "agent-sandbox";
    inherit (workspacePackage) version;
    inherit src;

    cargoLock.lockFile = "${src}/Cargo.lock";

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
    '';

    meta = with lib; {
      description = "Policy daemon, NFQUEUE enforcer, DNS cache, CLIs, netns enter helper, and Qt-wrapped UI";
      license = licenses.mit;
    };
  }
)
