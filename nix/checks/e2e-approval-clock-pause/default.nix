{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/approval-clock.nix { inherit lib pkgs inputs; }).pause
