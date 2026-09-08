{ pkgs, inputs, ... }:
let
  rust = (import "${inputs.self}/nix/lib/rust-toolchain.nix") { inherit pkgs; };
in
pkgs.mkShell {
  env = {
    CPATH =
      "${pkgs.qt6.qtbase.out}/include"
      + ":"
      + "${pkgs.qt6.qtbase.out}/include/QtWidgets"
      + ":"
      + "${pkgs.qt6.qtbase.out}/include/QtGui"
      + ":"
      + "${pkgs.qt6.qtbase.out}/include/QtCore"
      + ":"
      + "${pkgs.libbpf.out}/include";

    SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
  };

  nativeBuildInputs = with pkgs; [
    cargo-nextest
    cmake
    curl
    gitMinimal
    llvmPackages_22.clang-tools
    pkg-config
    rust.rustPlatform.bindgenHook
    rust.toolchain
  ];

  shellHook = ''
    if ! bash scripts/materialize-vendor.sh; then
      echo "ERROR: vendor/ is not materialized!" >&2
      echo "Run scripts/materialize-vendor.sh to fix this." >&2
    fi
  '';
}
