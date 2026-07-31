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

  preBuild = ''
    # rama-boring-sys 0.6.4 treats GCC 15's upstream false positives as errors.
    export CXXFLAGS="''${CXXFLAGS:-} -Wno-error=array-bounds -Wno-error=stringop-overflow"
  '';

  doCheck = true;

  # The target-qualified nextest hook cannot link rama-boring's generated
  # native symbols for proxy tests; run the workspace tests for the host.
  checkPhase = ''
    runHook preCheck
    cargo test --release --workspace --offline
    runHook postCheck
  '';

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
