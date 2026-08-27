{ pkgs, inputs, ... }:
let
  rust = (import "${inputs.self}/nix/lib/rust-toolchain.nix") { inherit pkgs; };
in
pkgs.mkShell {
  env.CPATH =
    "${pkgs.qt6.qtbase.out}/include"
    + ":"
    + "${pkgs.qt6.qtbase.out}/include/QtWidgets"
    + ":"
    + "${pkgs.qt6.qtbase.out}/include/QtGui"
    + ":"
    + "${pkgs.qt6.qtbase.out}/include/QtCore"
    + ":"
    + "${pkgs.libbpf.out}/include";

  nativeBuildInputs = with pkgs; [
    cargo-nextest
    cmake
    llvmPackages_22.clang-tools
    pkg-config
    rust.rustPlatform.bindgenHook
    rust.toolchain
  ];
}
