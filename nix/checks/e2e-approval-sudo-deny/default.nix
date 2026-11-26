{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/approval-sudo.nix { inherit lib pkgs inputs; }).mkCheck "deny"
