# agent-sandbox

`agent-sandbox` is a flake for running AI agent CLIs inside a tighter sandbox on NixOS.

It provides:

- wrapped agent binaries launched through `jail.nix`/bubblewrap
- a policy daemon that decides network and `sudo` access
- optional deny-by-default outbound networking
- interactive approval prompts with remembered decisions
- NixOS and Home Manager modules to install the whole stack

## What this project gives you

### NixOS module

`inputs.agent-sandbox.nixosModules.agent-sandbox`

Use this to install sandboxed versions of agent tools on a NixOS system.

The module can:

- wrap agent packages with sandbox launchers
- run `agent-sandbox-policyd`
- optionally put agents in a restricted network namespace
- proxy outbound web traffic through policy checks
- gate host `sudo` through the same approval flow

### Home Manager module

`inputs.agent-sandbox.homeModules.agent-sandbox`

Use this if you want approval prompts inside Oh My Pi sessions. It installs the OMP extension from `extensions/agent-sandbox/`.

## How it works

At a high level:

1. you launch an agent through a wrapped binary
2. the wrapper enters the sandbox before the agent starts
3. network access and `sudo` requests are sent to `policyd`
4. existing policy is applied first
5. unknown requests can block and prompt for approval
6. approvals can be remembered once, for the session, for the project, or globally

Main pieces:

- **wrapped CLI** — the sandboxed entrypoint you actually run
- **policyd** — policy merge, pending approvals, UI fan-out, and RPC endpoint
- **proxy + DNS cache** — lets network policy use hostnames instead of only raw IPs
- **UI** — either the OMP extension or `agent-sandbox-ui`

### RPC authorization

All clients share one Unix socket (`/run/agent-sandbox/policy.sock`). Policyd uses `SO_PEERCRED` to identify the connecting process and restricts what sandboxed peers may do:

- **From inside the sandbox** (agent netns when networking is enabled, otherwise a distinct mount namespace): `check` and `elevate` only, enough for the proxy and sudo guard to request policy decisions.
- **OMP inside the sandbox** can still act as UI after a successful `register_ui`:
    - the peer cmdline must look like OMP (`.omp/agent`, `oh-my-pi`, etc.)
    - policyd pins that OMP pid for the user
    - later `approve` / `deny` calls from the same OMP pid are allowed (including short-lived RPC connections from the extension)
- **From the host** (standalone `agent-sandbox-ui`, `agent-sandbox-approve`, etc.): full RPC access including `register_ui`, `approve`, and `deny`.

This blocks casual self-approval from tool subprocesses or `agent-sandbox-approve` running inside the sandbox. It is not bulletproof, since a very determined agent could try to mimic OMP but it should add enough friction for typical curious agent scenarios. Host-spawned UI (`agent-sandbox-ui` via `runuser`, or kdialog auto-spawn) remains the fallback when OMP is unavailable.

When networking is enabled, policyd is started with `--sandbox-netns /run/netns/<name>` so netns membership is authoritative. In sudo-only mode (no dedicated netns), mount-namespace comparison is used instead.

### Multiple agents at once

OMP, Codex, and other wrapped agents can run concurrently. They share the same merged **project** and **global** policy files, but each agent gets its own UI session:

- **OMP** registers as `ui_client: "omp"` and receives prompts for tool requests from its process tree only.
- **Other agents** use `agent-sandbox-ui` (auto-spawned kdialog when needed) matched by cwd/project paths.
- **Session-scoped** approvals apply only to the agent/UI session that created them, not every connected client.

## Policy model

`agent-sandbox` manages two policy areas:

- **network** — allow or deny outbound hosts/ports
- **sudo** — allow or deny command prefixes

Policy is merged from lowest to highest priority:

1. declarative NixOS configuration
2. per-user global policy file
3. per-project policy file
4. in-memory session/once decisions

Useful paths:

- global policy: `~/.config/agent-sandbox/policy.json`
- project policy: `<repo>/.agent-sandbox/policy.json`

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
    }
}
```

Notes:

- sudo rules use prefix matching, so `["systemctl"]` matches `systemctl restart nginx`
- network approvals can be saved at different granularities, including subdomains such as `*.example.com`
- project policy is intended for repo-local rules that should not become global defaults

## Approval flow

When an unknown request is blocked, a UI client can approve or deny it.

Available prompt paths:

- **OMP extension** — preferred when running inside Oh My Pi
- **`agent-sandbox-ui`** — standalone UI for other agent environments, using `kdialog` or `/dev/tty`
- **`agent-sandbox-approve`** — CLI for scripting or manual approval by pending id

Approvals are two-step:

1. choose approve or deny
2. choose scope/granularity

Examples:

- `foo.bar.baz.com` can be remembered as `foo.bar.baz.com`, `*.bar.baz.com`, or `*.baz.com`
- `sudo foo bar baz` can be remembered as the exact command, `sudo foo bar`, or `sudo foo`

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

| Option                                     | Meaning                                                        |
| ------------------------------------------ | -------------------------------------------------------------- |
| `agent-sandbox.enable`                     | Enable wrapped packages and install the policy tooling         |
| `agent-sandbox.network.enable`             | Enable restricted networking, proxying, and DNS cache support  |
| `agent-sandbox.sudoPolicy`                 | Either deny `sudo` entirely or gate it through approvals       |
| `agent-sandbox.policy.interactiveApproval` | Prompt instead of only relying on prewritten policy            |
| `agent-sandbox.policy.approvalTimeout`     | How long blocked requests wait for a UI decision               |
| `agent-sandbox.policy.autoSpawnPolicyUi`   | Start `agent-sandbox-ui` automatically when no UI is connected |

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

With the extension enabled, OMP becomes the primary approval UI.

## Typical use cases

- keep coding agents from making arbitrary outbound connections
- require explicit approval before an agent reaches a new host
- allow a project-specific API without opening access globally
- require approval before an agent can execute privileged host commands

## Repository layout

- `crates/agent-sandbox-core` — shared policy, RPC, host matching, context types
- `crates/agent-sandbox-policyd` — approval and policy daemon
- `crates/agent-sandbox-proxy` — network enforcement proxy
- `crates/agent-sandbox-dns` — DNS cache/proxy support
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
