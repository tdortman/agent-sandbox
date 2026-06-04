# OMP (oh-my-pi) extension: policy UI client for agent-sandbox policyd.
{
  lib,
  stdenvNoCC,
  inputs,
  ...
}:

stdenvNoCC.mkDerivation {
  pname = "agent-sandbox-omp-extension";
  version = "0.1.0";

  src = "${inputs.self}/extensions/agent-sandbox";

  dontUnpack = false;

  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    cp -r . "$out/"
    runHook postInstall
  '';

  meta = with lib; {
    description = "OMP extension for agent-sandbox policy prompts";
    license = licenses.mit;
  };
}
