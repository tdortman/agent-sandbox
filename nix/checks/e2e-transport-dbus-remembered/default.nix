{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  dbus = import ../e2e/transport-dbus.nix { inherit inputs lib pkgs; };
in
dbus.mkCheck {
  name = "remembered";
  node = "remembered";
  script = dbus.rememberedScript;
}
