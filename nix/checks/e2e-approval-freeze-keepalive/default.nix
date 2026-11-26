{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/approval-freeze.nix { inherit inputs lib pkgs; }).mkCheck "keepalive" [
  "keepalive"
  "idle"
]
