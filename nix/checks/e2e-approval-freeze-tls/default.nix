{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/approval-freeze.nix { inherit lib pkgs inputs; }).mkCheck "tls"
