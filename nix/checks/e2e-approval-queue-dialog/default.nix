{
  lib,
  pkgs,
  inputs,
  ...
}:
import ../e2e/approval-queue.nix { inherit inputs lib pkgs; } "dialog"
