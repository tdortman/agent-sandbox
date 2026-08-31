{ lib, pkgs, ... }:

let
  release = pkgs.fetchurl {
    url = "https://registry.npmjs.org/@deepseek-ai/dsh/-/dsh-0.1.1-rc.2.tgz";
    hash = "sha256-R+wF9FraWrh3ea4YqQRWtev/VCHcD/XBeWd9ZeHBYFc=";
  };
  src = pkgs.runCommand "dsh-source-0.1.1-rc.2" { nativeBuildInputs = [ pkgs.gnutar ]; } ''
    mkdir -p $out
    tar -xzf ${release} --strip-components=1 -C $out
    cp ${./package-lock.json} $out/package-lock.json
  '';
in
pkgs.buildNpmPackage rec {
  inherit src;
  pname = "dsh";
  version = "0.1.1-rc.2";
  nativeBuildInputs = [ pkgs.makeWrapper ];
  npmDepsHash = "sha256-wtozzqw6GiiwDNXXHSZgLMt5qF1rvFKnwfUePi9T2JY=";

  postInstall = ''
    # DSH's bash tool uses an absolute path that does not exist on NixOS.
    substituteInPlace \
      $out/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-terminal-bash/lib/index.js \
      --replace-fail '"/bin/bash"' '"${pkgs.bashInteractive}/bin/bash"'

    # Keep DSH's launcher neutral. The adapter and stopped-child provider are
    # selected by the shared profile environment, not by a policy fork.
    wrapProgram $out/bin/dsh \
      --set-default AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL 1 \
      --set-default AGENT_SANDBOX_CONTEXT_ADAPTER agent-sandbox \
      --set-default AGENT_SANDBOX_CHILD agent-sandbox-child
  '';

  dontNpmBuild = true;

  passthru = {
    sourceCommit = "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e";

    sourceTarball = pkgs.fetchurl {
      url = "https://github.com/deepseek-ai/deepseek-harness/archive/b150a551b8d465e31e418e1b2eaf5e79bbb7d28e.tar.gz";
      hash = "sha256-x41KqVuLWOXFKZvmeZ47btQFzOfvVbh+Rv+z86OdqBk=";
    };
  };

  meta = {
    description = "DeepSeek Harness profile bundle";
    homepage = "https://github.com/deepseek-ai/deepseek-harness";
    license = lib.licenses.mit;
    mainProgram = "dsh";
  };
}
