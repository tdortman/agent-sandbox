{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/approval-freeze.nix { inherit inputs lib pkgs; }).mkCheck "readahead" [
  "many"
  "download"
]
