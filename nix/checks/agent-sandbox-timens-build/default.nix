# Builds the agent-sandbox-timens kernel module against the newest kernel and
# the 6.18 LTS kernel, the oldest one the module supports.
{ pkgs, ... }:
let
  build = kernelPackages: kernelPackages.callPackage ../../packages/agent-sandbox-timens { };
in
pkgs.linkFarm "agent-sandbox-timens-build" {
  latest = build pkgs.linuxPackages_latest;
  linux_6_18 = build pkgs.linuxPackages_6_18;
}
