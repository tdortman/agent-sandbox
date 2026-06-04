# Home Manager: OMP policy UI extension for agent-sandbox.
{
  lib,
  pkgs,
  config,
  inputs,
  ...
}:

let
  flake = import ../../../lib/consumer.nix { inherit inputs pkgs; };

  cfg = config.programs.agent-sandbox.ompExtension;
  extensionPkg = flake.package "agent-sandbox-omp-extension";
  extensionPath = "${cfg.agentDir}/extensions/agent-sandbox";
in
{
  options.programs.agent-sandbox.ompExtension = {
    enable = lib.mkEnableOption ''
      Install the oh-my-pi agent-sandbox extension under the OMP agent directory.

      The extension registers as policy UI client ``omp`` with policyd and handles
      network and elevation approval prompts inside OMP sessions. Requires the
      NixOS ``agent-sandbox`` module (policy socket at
      ``/run/agent-sandbox/policy.sock`` by default).
    '';

    agentDir = lib.mkOption {
      type = lib.types.str;
      default = ".omp/agent";
      description = ''
        OMP agent config directory, relative to the home directory
        (typically ``~/.omp/agent``).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    home.file.${extensionPath} = {
      source = extensionPkg;
      recursive = true;
    };
  };
}
