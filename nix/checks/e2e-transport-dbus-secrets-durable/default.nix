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
  name = "secrets-durable";
  node = "dbus";
  script = dbus.secretsHelpers + dbus.secretsDurableScript;
}
