# agent-sandbox

`agent-sandbox` is a flake for running AI agent CLIs inside a tighter sandbox on NixOS.

Core pieces:

- NixOS module: wraps agent CLIs with bubblewrap launchers
- `agent-sandbox-policyd`: merges policy and owns approval state
- NFQUEUE + DNS cache: gates outbound TCP/UDP destinations by policy
- sudo guard: gates host elevation through the same approval flow
- optional fanotify monitor: gates filesystem opens from sandboxed processes
- Home Manager module: installs the Oh My Pi extension for network and sudo prompts

Use the NixOS module for sandboxed packages:

```nix
inputs.agent-sandbox.nixosModules.agent-sandbox
```

Use the Home Manager module when you want Oh My Pi to handle network and sudo approval prompts:

```nix
inputs.agent-sandbox.homeModules.agent-sandbox
```

## Runtime model

1. You run a wrapped agent binary.
2. The wrapper enters the sandbox before the agent starts.
3. Network checks, filesystem opens, and sudo requests go to `policyd`.
4. `policyd` applies declarative, global, project, session, and once policy.
5. Unknown requests block until a UI approves or denies them.

Components:

| Component | Job |
| --------- | --- |
| wrapped CLI | Sandboxed entrypoint you run |
| `policyd` | Policy merge, pending approvals, UI routing, RPC socket |
| NFQUEUE + DNS cache | Transport-layer network enforcement for arbitrary TCP/UDP ports |
| `fsmon` | Fanotify monitor scoped to each sandbox mount namespace |
| OMP extension | In-TUI prompts for network and sudo requests |
| `agent-sandbox-ui` | Standalone UI for filesystem prompts and non-OMP agents |

All clients share `/run/agent-sandbox/policy.sock`. `policyd` uses `SO_PEERCRED` to identify callers.

- Sandboxed tool processes may only request network, filesystem, or sudo checks.
- The OMP process may register as UI and approve network/sudo requests from its process tree.
- Host tools such as `agent-sandbox-ui` and `agent-sandbox-approve` may approve or deny pending requests.

Filesystem prompt limitation: fanotify blocks the process that opened the file. If OMP or an OMP tool opens the file, OMP may be blocked before its extension can render a prompt. For that reason filesystem approvals use `agent-sandbox-ui` (`kdialog` or `/dev/tty`) instead of the OMP extension. Network and sudo prompts still use the OMP extension.

OMP, Codex, and other wrapped agents can run at the same time. They share project and global policy files. Session-scoped approvals stay attached to the sandbox instance that created them, even when two agents run in the same project.

## Policy model

`agent-sandbox` manages three policy areas:

| Area | Rule shape |
| ---- | ---------- |
| network | host + port, with exact hosts or wildcard parent domains |
| filesystem | path + access kind |
| sudo | command prefix |

Policy merge order, lowest to highest priority:

1. declarative NixOS policy
2. global user policy: `~/.config/agent-sandbox/policy.json`
3. project policy: `<repo>/.agent-sandbox/policy.json`
4. in-memory session and once decisions

Example project policy:

```json
{
    "network": {
        "allow": [{ "host": "api.example.com", "port": 443 }],
        "deny": []
    },
    "sudo": {
        "allow": [{ "argv": ["systemctl", "restart"] }],
        "deny": []
    },
    "filesystem": {
        "allow": [{ "path": "~/projects/example", "access": "read_write" }],
        "deny": []
    }
}
```

Notes:

- `~/...` in `policy.json` expands to the invoking user's home. Policy writes also store paths under home in that form.
- Network approvals can target exact hosts or parent domains such as `*.example.com`.
- Filesystem prompts use the most specific access fanotify can prove: `read`, `write`, `read_write`, or `execute`. `read_write` covers both read and write. `all` also covers execute.
  Older kernels without `FAN_PRE_ACCESS` fall back to conservative open checks, which appear as `read_write`.
- Dynamic filesystem mode grants `all` access to the detected project root (`git rev-parse --show-toplevel`, falling back to `$PWD`).
  Agent work inside the current project should not prompt.
- Sudo rules use prefix matching, so `["systemctl"]` matches `systemctl restart nginx`.

## Approval flow

Unknown requests use the same three-step flow:

1. approve or deny
2. choose scope: once, session, project, or global
3. for session/project/global, choose the target granularity

Examples:

- `foo.bar.baz.com`: exact host, `*.bar.baz.com`, or `*.baz.com`
- `/home/user/projects/foo/data.txt`: exact file or a parent directory
- `sudo foo bar baz`: exact command, `sudo foo bar`, or `sudo foo`

Use `agent-sandbox-approve pending` to inspect blocked requests and approve them by id from a shell.

Network prompts are enforced at the transport layer. nftables queues outbound TCP SYN packets and UDP datagrams into `agent-sandbox-nfq`; the kernel holds the packet until policyd returns allow/deny. This is application-layer agnostic: HTTP(S), SSH, Git, package managers, and arbitrary ports use the same path. Plain DNS port 53 goes through `agent-sandbox-dns-forwarder`, which forwards to the system resolver and only records IP→hostname mappings for prompts. A tool with a short overall operation timeout may still give up if approval takes longer than that timeout.

## Minimal NixOS example

```nix
{
  inputs.agent-sandbox.url = "github:tdortman/agent-sandbox";
  inputs.agent-sandbox.inputs.nixpkgs.follows = "nixpkgs";
}
```

```nix
nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
  modules = [
    inputs.agent-sandbox.nixosModules.agent-sandbox

    ({ pkgs, ... }: {
      agent-sandbox = {
        enable = true;
        network.enable = true;
        packages = [
          {
            package = pkgs.some-agent;
            readwriteDirs = [ "~/.config/my-agent" ];
          }
        ];
      };
    })
  ];
};
```

When `network.enable = true`, the NixOS module also runs the policy/network helper services.

### High-value options

| Option                                            | Meaning                                                              |
| ------------------------------------------------- | -------------------------------------------------------------------- |
| `agent-sandbox.enable`                            | Enable wrapped packages and install the policy tooling               |
| `agent-sandbox.network.enable`                    | Enable restricted networking, NFQUEUE enforcement, and DNS cache support |
| `agent-sandbox.sudoPolicy`                        | Either deny `sudo` entirely or gate it through approvals             |
| `agent-sandbox.filesystem.dynamicApproval.enable` | Enable fanotify-backed filesystem approval for sandboxed processes   |
| `agent-sandbox.policy.interactiveApproval`        | Prompt instead of only relying on prewritten policy                  |
| `agent-sandbox.policy.approvalTimeout`            | How long blocked requests wait for a UI decision                     |
| `agent-sandbox.policy.autoSpawnPolicyUi`          | Start `agent-sandbox-ui` automatically when no UI is connected       |

For the full module surface, see `nix/modules/nixos/agent-sandbox/agent-sandbox.nix`.

## Minimal Home Manager example

```nix
homes.modules = [
  inputs.agent-sandbox.homeModules.agent-sandbox
];
```

```nix
programs.agent-sandbox.ompExtension.enable = true;
```

With the extension enabled, OMP becomes the approval UI for network and sudo requests. Filesystem prompts still use `agent-sandbox-ui` because fanotify can block OMP itself.

## Typical use cases

- keep coding agents from making arbitrary outbound connections
- require explicit approval before an agent reaches a new host
- allow a project-specific API without opening access globally
- require approval before an agent can execute privileged host commands

## Repository layout

- `crates/agent-sandbox-core` — shared policy, RPC, host matching, context types
- `crates/agent-sandbox-policyd` — approval and policy daemon
- `crates/agent-sandbox-nfq` — transport-layer NFQUEUE network enforcer
- `crates/agent-sandbox-dns` — DNS forwarder and IP→hostname cache support
- `crates/agent-sandbox-cli` — user-facing CLI tools
- `extensions/agent-sandbox` — OMP extension
- `nix/modules` — NixOS and Home Manager modules
- `nix/packages` — flake package definitions

## Development

```bash
nix develop
cargo test --workspace
cargo clippy-strict
```
