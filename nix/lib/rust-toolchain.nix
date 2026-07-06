# Shared Rust toolchain for both the devShell and the package derivation.
# Uses `selectLatestNightlyWith` so that updating the rust-overlay flake
# input automatically picks up the new nightly everywhere.
{
  pkgs,
}:
let
  toolchain = pkgs.rust-bin.stable.latest.default.override {
    extensions = [
      "rust-src"
      "rustfmt"
      "clippy"
      "rust-analyzer"
    ];
  };
in
{
  inherit toolchain;
  rustPlatform = pkgs.makeRustPlatform {
    cargo = toolchain;
    rustc = toolchain;
  };
}
