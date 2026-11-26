{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/proxy-http.nix { inherit inputs lib pkgs; }).mkCheck "policy" [
  "policy"
  "startup"
  "keepalive"
]
