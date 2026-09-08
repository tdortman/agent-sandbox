{
  lib,
  cmake,
  inputs,
  makeWrapper,
  pkgs,
  ...
}:
let
  # Checkout of the h3 repository at the revision pinned in Cargo.toml, used by
  # scripts/materialize-vendor.sh for the h3 crates.
  h3Source = pkgs.fetchgit {
    url = "https://github.com/hyperium/h3.git";
    rev = "c38a1af632afbbbc8f6716c196ad67f40bc122e3";
    hash = "sha256-9s9/OxQm3TTWpcNYK+BUKahro9acdbAqYRBZdnEp1O4=";
  };
  # Pristine archives of the crates patched by scripts/materialize-vendor.sh.
  # The lockfile records them as path dependencies, so cargoLock never fetches
  # them and the generated vendor directories have to be built here.
  patchedCrateArchives = [
    (pkgs.fetchurl {
      url = "https://static.crates.io/crates/rama-http-core/rama-http-core-0.4.0.crate";
      hash = "sha256-vYMlYwApeXVOYZU3oNWGGx8cjftQW3HDFMzXgbJpcyQ=";
    })
    (pkgs.fetchurl {
      url = "https://static.crates.io/crates/quinn/quinn-0.11.11.crate";
      hash = "sha256-DBpB5De2u9SJNyzUlx3hKOhchV9WxX8oPSD/AWz3wKg=";
    })
    (pkgs.fetchurl {
      url = "https://static.crates.io/crates/quinn-proto/quinn-proto-0.11.16.crate";
      hash = "sha256-L0v8AVJiud9jyIRQcs5ZBohT/1hyGAws4vEwOLlw5WA=";
    })
    (pkgs.fetchurl {
      url = "https://static.crates.io/crates/rustls/rustls-0.23.43.crate";
      hash = "sha256-AoM4bOAqvAFR4XYdCIAt/obBc7C0lK9cvAhldORT2gY=";
    })
  ];
  qtDialog = pkgs.stdenv.mkDerivation {
    src = ./qt-helper;

    nativeBuildInputs = [
      cmake
      pkgs.qt6.wrapQtAppsHook
    ];

    buildInputs = [
      pkgs.kdePackages.breeze
      pkgs.kdePackages.plasma-integration
      pkgs.qt6.qtbase
    ];

    postFixup = ''
      grep -aqF '${pkgs.kdePackages.breeze}/lib/qt-6/plugins' "$out/bin/agent-sandbox-qt-dialog"
      grep -aqF '${pkgs.kdePackages.plasma-integration}/lib/qt-6/plugins' "$out/bin/agent-sandbox-qt-dialog"
    '';

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

  postPatch = ''
    bash scripts/materialize-vendor.sh \
      ${lib.escapeShellArgs patchedCrateArchives} ${h3Source}
  '';

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

  useNextest = true;

  meta = with lib; {
    description = "Policy daemon, NFQUEUE enforcer, DNS cache, CLIs, netns enter helper, and Qt-wrapped UI";
    license = licenses.mit;
  };
}
