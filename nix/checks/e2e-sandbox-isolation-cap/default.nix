{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/sandbox-isolation.nix { inherit lib pkgs inputs; }).mkCheck "cap"
