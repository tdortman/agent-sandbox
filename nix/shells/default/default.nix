{ pkgs, inputs, ... }:
let
  rust = (import "${inputs.self}/nix/lib/rust-toolchain.nix") { inherit pkgs; };
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    rust.toolchain
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
      + "${pkgs.qt6.qtbase.out}/include/QtGui"
      + ":"
      + "${pkgs.qt6.qtbase.out}/include/QtCore";
  };
}
