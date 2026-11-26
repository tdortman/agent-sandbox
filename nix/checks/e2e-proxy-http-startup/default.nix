{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/proxy-http.nix { inherit lib pkgs inputs; }).mkCheck "startup"
