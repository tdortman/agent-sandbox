{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/approval-clock.nix { inherit inputs lib pkgs; }).pause
