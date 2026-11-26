{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/sandbox-isolation.nix { inherit inputs lib pkgs; }).mkCheck "cap"
