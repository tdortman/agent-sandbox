{
  lib,
  pkgs,
  inputs,
  ...
}:
(import ../e2e/approval-sudo.nix { inherit inputs lib pkgs; }).mkCheck "approve" [
  "approve"
  "approve-unlisted"
]
