# sudo shim for jailed agents: deny, or delegate to policyd.
{
  pkgs,
  policy,
  policyPkg,
}:

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
    # -n is accepted and ignored: approval still goes through the policy UI.
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -n | --non-interactive) shift ;;
        --)
          shift
          break
          ;;
        -*)
          echo "sudo: option $1 is not supported in the agent sandbox" >&2
          exit 1
          ;;
        *) break ;;
      esac
    done
    if [ "$#" -eq 0 ]; then
      echo "usage: sudo <command>" >&2
      exit 1
    fi
    ${body}
  '';
}
