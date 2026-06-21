# OMP (oh-my-pi) extension: policy UI client for agent-sandbox policyd.
{
  lib,
  stdenv,
  nodejs,
  inputs,
  ...
}:

stdenv.mkDerivation {
  pname = "agent-sandbox-omp-extension";
  version = "0.1.0";

  src = "${inputs.self}/extensions/agent-sandbox";

  nativeBuildInputs = [ nodejs ];

  buildPhase = ''
    runHook preBuild
    cc -shared -fPIC -o fdctl.node fdctl.c \
      -I"${nodejs}/include/node"
    runHook postBuild
  '';

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
