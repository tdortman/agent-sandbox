{ pkgs, ... }:
let
  rust-toolchain = pkgs.rust-bin.stable.latest.default.override {
    extensions = [
      "rust-src"
      "rustfmt"
      "clippy"
      "rust-analyzer"
    ];
  };
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    rust-toolchain
    pkg-config
    cmake
    llvmPackages_22.clang-tools
    cargo-nextest
  ];

  env = {
    CPATH =
      "${pkgs.qt6.qtbase.out}/include"
      + ":"
      + "${pkgs.qt6.qtbase.out}/include/QtWidgets"
      + ":"
      + "${pkgs.qt6.qtbase.out}/include/QtGui";
  };
}
