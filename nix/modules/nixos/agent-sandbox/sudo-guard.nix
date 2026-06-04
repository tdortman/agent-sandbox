# sudo shim for jailed agents: deny, or delegate to policyd (OMP approval).
{ pkgs, policyPkg, policy }:
let
  body =
    if policy == "deny" then
      ''
        echo "agent-sandbox: sudo is disabled in the agent sandbox." >&2
        exit 1
      ''
    else if policy == "approve" then
      ''
        exec agent-sandbox-elevate "$@"
      ''
    else
      throw "agent-sandbox.sudoPolicy must be deny or approve, got: ${policy}";
in
pkgs.writeShellApplication {
  name = "sudo";
  runtimeInputs = if policy == "approve" then [ policyPkg ] else [ ];
  text = ''
    set -euo pipefail
    if [ "$#" -eq 0 ]; then
      echo "agent-sandbox: usage: sudo <command>" >&2
      exit 1
    fi
    printf 'agent-sandbox: elevation requested:' >&2
    printf ' %q' "$@" >&2
    echo >&2
    ${body}
  '';
}
