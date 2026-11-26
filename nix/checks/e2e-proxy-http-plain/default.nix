{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/proxy-http.nix { inherit inputs lib pkgs; }).mkCheck "plain" [
  "conncap"
  "dial"
  "halfclose"
  "leading-crlf"
  "methods"
]
