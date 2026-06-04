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
  ];
}
