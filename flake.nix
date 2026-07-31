{

  description = "Policy stack and NixOS module for sandboxed AI agent CLIs";

  outputs =
    inputs:
    inputs.snowfall-lib.mkFlake {
      inherit inputs;

      snowfall = {
        namespace = "agent-sandbox";
        root = ./nix;
      };

      src = ./.;
      alias.packages.default = "agent-sandbox";

      overlays = [
        inputs.rust-overlay.overlays.default
      ];

      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      outputs-builder =
        channels:
        let
          treefmt = inputs.treefmt-nix.lib.evalModule channels.nixpkgs {
            imports = [ inputs.pedantix.treefmtModules.default ];

            programs.pedantix = {
              enable = true;

              settings = {
                attrs = {
                  blank-lines = 1;
                  blank-lines-mode = "multiline";
                  flatten = true;
                  merge = true;
                  name-style = "identifier";
                };

                formatter = "nixfmt";
                inherit-placement = "front";
                inherits.name-style = "identifier";
                lets.name-style = "identifier";
                lists.sort = false;
              };
            };

            projectRootFile = "flake.nix";
          };
        in
        {
          checks.formatting = treefmt.config.build.check inputs.self;
          formatter = treefmt.config.build.wrapper;
        };
    };

  inputs = {
    jail-nix.url = "sourcehut:~alexdavid/jail.nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    pedantix = {
      inputs = {
        nixpkgs.follows = "nixpkgs";
        treefmt-nix.follows = "treefmt-nix";
      };

      url = "github:swarsel/pedantix";
    };

    rust-overlay = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:oxalica/rust-overlay";
    };

    snowfall-lib = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:anntnzrb/snowfall-lib";
    };

    treefmt-nix = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:numtide/treefmt-nix";
    };
  };
}
