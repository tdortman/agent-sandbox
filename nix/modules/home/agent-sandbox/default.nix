{
  config,
  lib,
  inputs,
  ...
}:
{
  options.agent-sandbox.tern-oauth.enable = lib.mkEnableOption "the Tern plugin for sandbox OAuth links";

  config = lib.mkIf config.agent-sandbox.tern-oauth.enable {
    xdg.configFile."tern/plugins/agent-sandbox-oauth".source = "${inputs.self}/integrations/tern-oauth";
  };
}
