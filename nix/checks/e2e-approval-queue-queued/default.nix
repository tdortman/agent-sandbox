{
  lib,
  pkgs,
  inputs,
  ...
}:
# coalesce runs last: it leaves the second sandbox's prompt pending, and the
# CLI cannot settle another sandbox's prompt.
import ../e2e/approval-queue.nix { inherit inputs lib pkgs; } "queued" [
  "window"
  "dialog"
  "coalesce"
]
