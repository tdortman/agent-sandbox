# sudo shim for jailed agents: deny, or delegate to policyd.
{ pkgs, policyPkg, policy }:
let
  body =
    if policy == "deny" then
      ''
        echo "sudo is disabled in the agent sandbox." >&2
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
      echo "usage: sudo <command>" >&2
      exit 1
    fi
    printf ' %q' "$@" >&2
    echo >&2
    ${body}
  '';
}
