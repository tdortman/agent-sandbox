{

  description = "Policy stack and NixOS module for sandboxed AI agent CLIs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    snowfall-lib = {
      url = "github:anntnzrb/snowfall-lib";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    jail-nix.url = "git+https://git.sr.ht/~alexdavid/jail.nix";
  };

  outputs =
    inputs:
    inputs.snowfall-lib.mkFlake {
      inherit inputs;
      src = ./.;

      snowfall.root = ./nix;
      snowfall.namespace = "agent-sandbox";

      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      overlays = [
        inputs.rust-overlay.overlays.default
      ];

      alias.packages.default = "agent-sandbox";
    };
}
