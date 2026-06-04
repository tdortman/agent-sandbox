{
  lib,
  inputs,
  pkg-config,
  rustPlatform,
  makeWrapper,
  pkgs,
  ...
}:
let
  kdialog = pkgs.kdePackages.kdialog;
in
rustPlatform.buildRustPackage (
  let
    src = inputs.self;
    workspacePackage = (fromTOML (builtins.readFile "${src}/Cargo.toml")).workspace.package;
  in
  {
    pname = "agent-sandbox";
    version = workspacePackage.version;
    inherit src;

    cargoLock.lockFile = "${src}/Cargo.lock";

    nativeBuildInputs = [
      pkg-config
      makeWrapper
    ];

    doCheck = true;

    postInstall = ''
      wrapProgram $out/bin/agent-sandbox-ui \
        --prefix PATH : ${lib.makeBinPath [ kdialog ]} \
        --set-default AGENT_SANDBOX_KDIALOG ${kdialog}/bin/kdialog
    '';

    meta = with lib; {
      description = "Policy daemon, proxy, DNS cache, CLIs, netns enter helper, and kdialog-wrapped UI";
      license = licenses.mit;
    };
  }
)
