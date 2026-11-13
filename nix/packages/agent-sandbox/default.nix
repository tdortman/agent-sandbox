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
    rev = "43745ad87e95b0c035ac9c547aad467303213425";
    hash = "sha256-Dmz2HcEkIdypr3HVG4SlSwTu+e00psQVB9SUoCsXZ7Q=";
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
      url = "https://static.crates.io/crates/quinn/quinn-0.11.12.crate";
      hash = "sha256-QFHiPpGFwlWn4z71nNvKh6ItNZBS7s0i/GuQH7N9nRE=";
    })
    (pkgs.fetchurl {
      url = "https://static.crates.io/crates/quinn-proto/quinn-proto-0.11.19.crate";
      hash = "sha256-DnUMylX+TwQ5oV0LtSnallHnmZPo5yxhqJmjbUYr774=";
    })
    (pkgs.fetchurl {
      url = "https://static.crates.io/crates/rustls/rustls-0.23.46.crate";
      hash = "sha256-SOE72MDpNlxDz6XJ6PmtSdPIREkmyarIGeDk3FA8j98=";
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
    pkgs.pkg-config
    rust.rustPlatform.bindgenHook
  ];

  buildInputs = [
    pkgs.aws-lc
  ];

  cargoLock = {
    lockFile = "${src}/Cargo.lock";

    outputHashes = {
      "h3-quinn-0.0.10" = "sha256-Dmz2HcEkIdypr3HVG4SlSwTu+e00psQVB9SUoCsXZ7Q=";
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
