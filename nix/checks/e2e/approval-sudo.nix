{
  lib,
  pkgs,
  inputs,
}:
let
  inherit (e2e)
    baseNode
    installPolicy
    module
    sudoApprovePackages
    sudoDenyPackages
    sudoPolicy
    ;
  e2e = import ./common.nix { inherit inputs lib pkgs; };

  nodes = {
    sudo-approve =
      _:
      lib.recursiveUpdate baseNode (
        lib.recursiveUpdate (installPolicy sudoPolicy) {
          imports = [ module ];

          agent-sandbox = {
            enable = true;
            packages = sudoApprovePackages;

            policy = {
              interactiveApproval = false;
              uiBackend = "none";
            };

            sudoPolicy = "approve";
          };
        }
      );

    sudo-deny =
      _:
      baseNode
      // {
        imports = [ module ];

        agent-sandbox = {
          enable = true;
          packages = sudoDenyPackages;
          sudoPolicy = "deny";
        };
      };
  };

  scenarios = {
    # Sudo deny is an immediate guard failure.
    deny = {
      node = "sudo-deny";
      script = ''
        sudo_deny.wait_for_unit("multi-user.target")
        sandbox_shell(sudo_deny, "sandbox-sudo-deny-bash", 'sudo id 2>&1 | grep -q "sudo is disabled"')
      '';
    };

    # Approve mode executes the declaratively allowed command with arguments
    # but rejects sudo options.
    approve = {
      node = "sudo-approve";
      script = ''
        sudo_approve.wait_for_unit("multi-user.target")
        sudo_approve.wait_for_unit("agent-sandbox-vm-policy.service")
        sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", 'sudo id | grep -q "uid=0(root)"')
        sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "test \"$(sudo id -u)\" = 0")
        sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "sudo -u nobody id", expect_success=False)
      '';
    };

    # A command outside the declarative allow-list is queued for approval with
    # no UI to answer; the request must run into its ~60 s timeout and fail.
    approve-unlisted = {
      node = "sudo-approve";
      script = ''
        sudo_approve.wait_for_unit("multi-user.target")
        sudo_approve.wait_for_unit("agent-sandbox-vm-policy.service")
        sandbox_shell(sudo_approve, "sandbox-sudo-approve-bash", "sudo sh -c id", expect_success=False)
      '';
    };
  };
in
{
  # Boots only the scenario's node.
  mkCheck =
    scenario:
    let
      inherit (scenarios.${scenario}) node script;
    in
    pkgs.testers.runNixOSTest (_: {
      name = "e2e-approval-sudo-${scenario}";
      node.specialArgs = { inherit inputs; };
      nodes.${node} = nodes.${node};
      testScript = ''
        import shlex

        def sandbox_shell(node, package, script, *, expect_success=True):
            line = f"runuser -u sandbox -- {package} -c {shlex.quote(script)}"
            check = node.succeed if expect_success else node.fail
            return check(line, timeout=60)

        start_all()
        ${script}
      '';
    });
}
