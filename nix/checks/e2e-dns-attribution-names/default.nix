{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/dns-attribution.nix { inherit inputs lib pkgs; }).mkCheck "names" [
  "forged"
  "forged-tcp"
  "shared"
  "hostile"
  "many"
  "rawtcp"
]
