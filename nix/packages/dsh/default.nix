{ lib, pkgs, ... }:

let
  harnessPkg = pkgs.agent-sandbox.harness-integrations;
  sandboxPkg = pkgs.agent-sandbox.agent-sandbox;
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
  npmDepsHash = "sha256-wtozzqw6GiiwDNXXHSZgLMt5qF1rvFKnwfUePi9T2JY=";

  postInstall = ''
    # DSH's bash tool uses an absolute path that does not exist on NixOS.
    substituteInPlace \
      $out/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-terminal-bash/lib/index.js \
      --replace-fail '"/bin/bash"' '"${pkgs.bashInteractive}/bin/bash"'

    # Keep the installed CLI thin: the shared adapter owns registration, while
    # the harness-specific process provider remains an environment seam.
    mv $out/bin/dsh $out/bin/dsh-unwrapped
    install -Dm0755 /dev/stdin $out/bin/dsh <<'DSH'
    #!${pkgs.bash}/bin/bash
    set -euo pipefail
    export AGENT_SANDBOX_CONTEXT_ADAPTER_PROTOCOL=1
    export AGENT_SANDBOX_CONTEXT_ADAPTER="${harnessPkg}/bin/agent-sandbox-context-adapter"
    export AGENT_SANDBOX_CHILD="${harnessPkg}/bin/agent-sandbox-child"
    export AGENT_SANDBOX_PROXY="${sandboxPkg}/bin/agent-sandbox-proxy"
    export AGENT_SANDBOX_DBUS_PROXY="${sandboxPkg}/bin/agent-sandbox-dbus-proxy"
    exec ${harnessPkg}/bin/agent-sandbox-context-adapter -- "@out@/bin/dsh-unwrapped" "$@"
    DSH
    substituteInPlace $out/bin/dsh --replace-fail @out@ $out
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
