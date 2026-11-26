{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/dns-attribution.nix { inherit lib pkgs inputs; }).mkCheck "sched"
