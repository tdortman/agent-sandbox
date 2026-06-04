# Resolve agent-sandbox flake outputs when NixOS/HM modules run in a consumer flake.
#
# In dotfiles, `inputs.self` is the host flake, packages live on `inputs.agent-sandbox`.
# When this repo is evaluated standalone, `inputs.self` is correct.
{ inputs, pkgs }:
let
  selfFlake = inputs.agent-sandbox or inputs.self;
  system = pkgs.stdenv.hostPlatform.system;
in
{
  packages = selfFlake.packages.${system};
  package = name: selfFlake.packages.${system}.${name};

  jail-nix = inputs.jail-nix or selfFlake.inputs.jail-nix;
}
