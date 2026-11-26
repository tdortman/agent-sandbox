{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  dbus = import ../e2e/transport-dbus.nix { inherit lib pkgs inputs; };
in
dbus.mkCheck {
  name = "secrets-isolation";
  node = "dbus";
  script = dbus.secretsHelpers + dbus.secretsIsolationScript;
}
