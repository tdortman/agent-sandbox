# fusermount shim for jailed agents: asks policyd to mount in the sandbox.
{ pkgs, policyPkg }:

# Plain copies, not symlinks: bubblewrap binds the shim over the hidden
# /run/wrappers/bin entries, and a copy keeps the store closure reachable.
pkgs.runCommand "agent-sandbox-fusermount" { } ''
  install -Dm755 ${policyPkg}/bin/agent-sandbox-fusermount $out/bin/fusermount3
  install -Dm755 ${policyPkg}/bin/agent-sandbox-fusermount $out/bin/fusermount
''
