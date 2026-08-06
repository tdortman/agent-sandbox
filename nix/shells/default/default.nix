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
    + "${pkgs.qt6.qtbase.out}/include/QtCore";

  nativeBuildInputs = with pkgs; [
    cargo-nextest
    cmake
    llvmPackages_22.clang-tools
    pkg-config
    rust.rustPlatform.bindgenHook
    rust.toolchain
  ];

  shellHook = ''
    # rama-boring-sys 0.6.4 treats GCC 15's upstream false positives as errors.
    export CXXFLAGS="''${CXXFLAGS:-} -Wno-error=array-bounds -Wno-error=stringop-overflow"
  '';
}
