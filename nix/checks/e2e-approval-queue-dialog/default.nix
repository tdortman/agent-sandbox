{
  lib,
  pkgs,
  inputs,
  ...
}:
import ../e2e/approval-queue.nix { inherit lib pkgs inputs; } "dialog"
