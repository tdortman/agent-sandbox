import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { execFile } from "node:child_process";
import * as net from "node:net";
import { type ApprovalScope, policyRpc } from "./policy-client";

type ApprovalTarget =
  | { kind: "network_host"; host: string }
  | { kind: "sudo_command"; argv: string[] };
type ScopeOption = {
  label: string;
  scope: ApprovalScope;
  target?: ApprovalTarget;
};

type PromptAction = "approve" | "deny";

type NetworkRequest = {
  type: "network_request";
  id: string;
  host: string;
  port: number;
  scheme?: string;
  url?: string;
  cwd?: string;
  home?: string;
  project_root?: string;
};

type ElevationRequest = {
  type: "elevation_request";
  id: string;
  argv: string[];
  cwd?: string;
  home?: string;
  project_root?: string;
};

type FilesystemRequest = {
  type: "filesystem_request";
  id: string;
  path: string;
  access: string;
  cwd?: string;
  home?: string;
  project_root?: string;
};

type PolicyMessage =
  | NetworkRequest
  | ElevationRequest
  | FilesystemRequest
  | Record<string, unknown>;

const ACTION_OPTIONS = ["Allow", "Deny"] as const;

const DEFAULT_SOCKET = "/run/agent-sandbox/policy.sock";

function parseLines(
  buf: string,
  chunk: string,
): { rest: string; lines: string[] } {
  let rest = buf + chunk;
  const lines: string[] = [];
  for (;;) {
    const idx = rest.indexOf("\n");
    if (idx === -1) break;
    const line = rest.slice(0, idx);
    rest = rest.slice(idx + 1);
    if (line.length > 0) lines.push(line);
  }
  return { rest, lines };
}

function readOneJsonLine(socket: net.Socket): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let buf = "";
    const onData = (chunk: string) => {
      buf += chunk;
      const idx = buf.indexOf("\n");
      if (idx === -1) return;
      socket.off("data", onData);
      socket.off("error", onError);
      const line = buf.slice(0, idx);
      try {
        resolve(JSON.parse(line) as Record<string, unknown>);
      } catch (err) {
        reject(err);
      }
    };
    const onError = (err: Error) => {
      socket.off("data", onData);
      reject(err);
    };
    socket.on("data", onData);
    socket.on("error", onError);
  });
}

export default function agentSandboxExtension(pi: ExtensionAPI) {
  pi.setLabel("Agent sandbox");

  let uiSocket: net.Socket | null = null;
  let policySessionId: string | null = null;
  let lineBuf = "";
  let reconnectTimer: ReturnType<typeof setInterval> | null = null;
  let currentContext: ExtensionContext | null = null;
  const home = process.env.HOME ?? "";
  const projectRoot = process.env.AGENT_SANDBOX_PROJECT_ROOT ?? "";

  // Resolver queue for sendPolicyRpc: each entry is a [resolve, reject] pair.
  type RpcResolver = [(value: Record<string, unknown>) => void, (err: Error) => void];
  const rpcQueue: RpcResolver[] = [];

  function notify(message: string): void {
    currentContext?.ui.notify?.(message);
  }

  function commandArgs(input: unknown): string[] {
    if (Array.isArray(input)) return input.map(String);
    if (
      input &&
      typeof input === "object" &&
      Array.isArray((input as { args?: unknown }).args)
    ) {
      return (input as { args: unknown[] }).args.map(String);
    }
    return [];
  }

  function sandboxContext(req?: { cwd?: string; home?: string; project_root?: string }) {
    return {
      cwd: req?.cwd ?? process.env.AGENT_SANDBOX_CWD ?? process.cwd(),
      home: req?.home ?? home,
      project_root: req?.project_root ?? (projectRoot || undefined),
    };
  }

  function rpcContext(req?: { cwd?: string; home?: string; project_root?: string }) {
    const { cwd, home, project_root } = sandboxContext(req);
    return {
      ctx: {
        cwd,
        home,
        ...(project_root ? { project_root } : {}),
        ...(process.env.AGENT_SANDBOX_SESSION_ID
          ? { sandbox_session_id: process.env.AGENT_SANDBOX_SESSION_ID }
          : {}),
      },
    };
  }

  function disconnectPolicyUi(): void {
    const socket = uiSocket;
    uiSocket = null;
    policySessionId = null;
    lineBuf = "";
    if (!socket) return;
    socket.destroy();
  }

  function isIpv4(host: string): boolean {
    const parts = host.split(".");
    if (parts.length !== 4) return false;
    return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }
  function isIpv6(host: string): boolean {
    return host.includes(":") || /^\[[^\]]+\]$/.test(host);
  }
  function approvalHostPatterns(host: string): string[] {
    const normalized = host.trim().toLowerCase().replace(/\.+$/, "");
    if (!normalized) return [];
    const labels = normalized.split(".");
    const patterns = [normalized];
    if (isIpv4(normalized)) {
      for (let len = labels.length - 1; len >= 1; len -= 1) {
        patterns.push(`${labels.slice(0, len).join(".")}.*`);
      }
    } else if (normalized.includes(":")) {
      const cleaned = normalized.replace(/^\[|\]$/g, "");
      const segments = expandIpv6Segments(cleaned);
      if (segments) {
        for (let len = 7; len >= 1; len -= 1) {
          patterns.push(`${segments.slice(0, len).join(":")}:*`);
        }
      }
    } else {
      for (let index = 1; index < labels.length; index += 1) {
        const suffix = labels.slice(index).join(".");
        if (suffix.includes(".")) {
          patterns.push(`*.${suffix}`);
        }
      }
    }
    return patterns;
  }
  function expandIpv6Segments(addr: string): string[] | null {
    const parts = addr.split("::");
    if (parts.length > 2) return null;
    let left: string[];
    let right: string[];
    if (parts.length === 2) {
      left = parts[0] ? parts[0].split(":") : [];
      right = parts[1] ? parts[1].split(":") : [];
    } else {
      left = addr.split(":");
      right = [];
    }
    if (left.length + right.length > 8) return null;
    for (const p of [...left, ...right]) {
      if (p.length > 4 || !/^[0-9a-f]*$/i.test(p)) return null;
    }
    const expanded: string[] = [];
    for (const s of left) expanded.push(s === "" ? "0" : s.replace(/^0+(?!$)/, "") || "0");
    while (expanded.length < 8 - right.length) expanded.push("0");
    for (const s of right) expanded.push(s === "" ? "0" : s.replace(/^0+(?!$)/, "") || "0");
    return expanded;
  }
  function sudoApprovalPrefixes(argv: string[]): string[][] {
    const prefixes: string[][] = [];
    for (let length = argv.length; length >= 1; length -= 1) {
      prefixes.push(argv.slice(0, length));
    }
    return prefixes;
  }

  function formatSudoCommand(argv: string[]): string {
    return argv.length > 0 ? `sudo ${argv.join(" ")}` : "sudo";
  }
  // ---- Label helpers (matching qt-dialog) ----

  function scopeLabel(scope: ApprovalScope): string {
    switch (scope) {
      case "once":    return "Once";
      case "session": return "This session";
      case "project": return "This project";
      case "global":  return "Globally";
    }
  }

  function scopeOnlyOptions(sessionAvailable: boolean): ScopeOption[] {
    const options: ScopeOption[] = [{ label: "Once", scope: "once" }];
    if (sessionAvailable) {
      options.push({ label: "This session", scope: "session" });
    }
    options.push({ label: "This project", scope: "project" });
    options.push({ label: "Globally", scope: "global" });
    return options;
  }

  function networkTargetOptions(host: string, scope: ApprovalScope): ScopeOption[] {
    return approvalHostPatterns(host).map((candidate) => ({
      label: candidate,
      scope,
      target: { kind: "network_host" as const, host: candidate },
    }));
  }

  function sudoTargetOptions(
    argv: string[],
    scope: ApprovalScope,
  ): ScopeOption[] {
    return sudoApprovalPrefixes(argv).map((prefix) => {
      const cmd = formatSudoCommand(prefix);
      return {
        label: cmd,
        scope,
        target: { kind: "sudo_command" as const, argv: prefix },
      };
    });
  }

  function filesystemTargetOptions(
    path: string,
    homeDir: string,
    scope: ApprovalScope,
  ): ScopeOption[] {
    const parts = path.replace(/\/+$/, "").split("/").filter(Boolean);
    const candidates: string[] = [];
    let current = "";
    for (const part of parts) {
      current += "/" + part;
      candidates.push(current);
    }
    if (homeDir && path.startsWith(homeDir)) candidates.push(homeDir);
    candidates.push("/");
    return candidates.reverse().map((c) => ({ label: c, scope }));
  }

  function verb(action: PromptAction): string {
    return action === "approve" ? "allow" : "deny";
  }

  async function chooseAction(
    title: string,
    ctx: ExtensionContext,
    opts?: { signal?: AbortSignal },
  ): Promise<PromptAction | undefined> {
    const choice = await ctx.ui.select(title, [...ACTION_OPTIONS], opts);
    if (choice === "Allow") return "approve";
    if (choice === "Deny") return "deny";
    return undefined;
  }

  async function chooseOption(
    title: string,
    options: ScopeOption[],
    ctx: ExtensionContext,
    opts?: { signal?: AbortSignal },
  ): Promise<ScopeOption | undefined> {
    const labels = options.map((o) => o.label);
    const choice = await ctx.ui.select(title, labels, opts);
    if (choice === undefined) return undefined;
    const idx = labels.indexOf(choice);
    if (idx === -1) return undefined;
    return options[idx];
  }

  // ---- Policy RPC on the active connection ----

  /** Send a JSON-line RPC and resolve with the next non-`type` reply. */
  function sendPolicyRpc(req: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      if (!uiSocket || uiSocket.destroyed) {
        reject(new Error("not connected to policy UI"));
        return;
      }
      rpcQueue.push([resolve, reject]);
      uiSocket.write(`${JSON.stringify(req)}\n`);
    });
  }

  function onPolicyMessage(msg: PolicyMessage): void {
    // Messages with `type` are pushes (network_request, elevation_request, filesystem_request).
    if ("type" in msg && typeof msg.type === "string") {
      void handlePolicyPush(msg.type, msg as Record<string, unknown>).catch((err: unknown) => {
        notify(`agent-sandbox: prompt handler failed: ${(err as Error).message}`);
      });
      return;
    }
    // Messages without `type` are RPC replies.
    const entry = rpcQueue.shift();
    if (entry) {
      entry[0](msg as Record<string, unknown>);
    } else if ("error" in msg && typeof msg.error === "string") {
      notify(`agent-sandbox: policy socket error: ${msg.error}`);
    }
  }

  // ---- Policy push handlers ----

  async function handlePolicyPush(
    msgType: string,
    msg: Record<string, unknown>,
  ): Promise<void> {
    const ctx = currentContext;
    if (!ctx) {
      notify(`agent-sandbox: policy prompt (${msgType}) arrived before session context`);
      return;
    }
    switch (msgType) {
      case "network_request": {
        const req = msg as unknown as NetworkRequest;
        await handleNetworkRequest(req, ctx);
        break;
      }
      case "elevation_request": {
        const req = msg as unknown as ElevationRequest;
        await handleElevationRequest(req, ctx);
        break;
      }
      case "filesystem_request": {
        const req = msg as unknown as FilesystemRequest;
        await handleFilesystemRequest(req, ctx);
        break;
      }
    }
  }

  async function handleNetworkRequest(
    req: NetworkRequest,
    ctx: ExtensionContext,
  ): Promise<void> {
    const host = req.host;
    const port = req.port;
    const scheme = req.scheme ?? "tcp";
    const url = `${scheme}://${host}:${port}`;

    // Step 1: Allow or Deny
    let action: PromptAction | undefined;
    try {
      action = await chooseAction(`agent-sandbox: ${url}`, ctx);
    } catch (err) {
      ctx.ui.notify?.(`agent-sandbox: network prompt failed: ${(err as Error).message}`);
      return;
    }
    if (!action) return;

    // Step 2: Choose scope
    let choice: ScopeOption | undefined;
    try {
      choice = await chooseOption(
        `agent-sandbox: ${verb(action)} ${url} scope?`,
        scopeOnlyOptions(true),
        ctx,
      );
    } catch (err) {
      ctx.ui.notify?.(`agent-sandbox: network scope prompt failed: ${(err as Error).message}`);
      return;
    }
    if (!choice) return;

    // Step 3: For non-Once, choose target domain pattern
    if (choice.scope !== "once") {
      try {
        const targets = networkTargetOptions(host, choice.scope);
        if (targets.length > 1) {
          const targetChoice = await chooseOption(
            `agent-sandbox: ${verb(action)} ${url} target?`,
            targets,
            ctx,
          );
          if (targetChoice) choice = targetChoice;
        }
      } catch (err) {
        ctx.ui.notify?.(
          `agent-sandbox: network target prompt failed: ${(err as Error).message}`,
        );
        return;
      }
    }

    try {
      await submitDecision({ approve: action === "approve", id: req.id }, choice, req);
    } catch (err) {
      ctx.ui.notify?.(
        `agent-sandbox: network ${verb(action)} failed: ${(err as Error).message}`,
      );
    }
  }

  async function handleElevationRequest(
    req: ElevationRequest,
    ctx: ExtensionContext,
  ): Promise<void> {
    const argv = req.argv;
    const title = `agent-sandbox: sudo ${argv.join(" ")}`;

    // Step 1: Allow or Deny
    let action: PromptAction | undefined;
    try {
      action = await chooseAction(title, ctx);
    } catch (err) {
      ctx.ui.notify?.(`agent-sandbox: elevation prompt failed: ${(err as Error).message}`);
      return;
    }
    if (!action) return;

    // Step 2: Choose scope
    let choice: ScopeOption | undefined;
    try {
      choice = await chooseOption(
        `agent-sandbox: ${verb(action)} sudo scope?`,
        scopeOnlyOptions(true),
        ctx,
      );
    } catch (err) {
      ctx.ui.notify?.(
        `agent-sandbox: elevation scope prompt failed: ${(err as Error).message}`,
      );
      return;
    }
    if (!choice) return;

    // Step 3: For non-Once, choose command prefix
    if (choice.scope !== "once") {
      try {
        const targets = sudoTargetOptions(argv, choice.scope);
        if (targets.length > 1) {
          const targetChoice = await chooseOption(
            `agent-sandbox: ${verb(action)} sudo target?`,
            targets,
            ctx,
          );
          if (targetChoice) choice = targetChoice;
        }
      } catch (err) {
        ctx.ui.notify?.(
          `agent-sandbox: elevation target prompt failed: ${(err as Error).message}`,
        );
        return;
      }
    }

    try {
      await submitDecision({ approve: action === "approve", id: req.id }, choice, req);
    } catch (err) {
      ctx.ui.notify?.(
        `agent-sandbox: elevation ${verb(action)} failed: ${(err as Error).message}`,
      );
    }
  }

  async function handleFilesystemRequest(
    req: FilesystemRequest,
    ctx: ExtensionContext,
  ): Promise<void> {
    const path = req.path;
    const access = req.access;

    // Step 1: Allow or Deny
    let action: PromptAction | undefined;
    try {
      action = await chooseAction(
        `agent-sandbox: filesystem ${access} ${path}`,
        ctx,
      );
    } catch (err) {
      ctx.ui.notify?.(`agent-sandbox: filesystem prompt failed: ${(err as Error).message}`);
      return;
    }
    if (!action) return;

    // Step 2: Choose scope
    let choice: ScopeOption | undefined;
    try {
      choice = await chooseOption(
        `agent-sandbox: ${verb(action)} filesystem scope?`,
        scopeOnlyOptions(true),
        ctx,
      );
    } catch (err) {
      ctx.ui.notify?.(
        `agent-sandbox: filesystem scope prompt failed: ${(err as Error).message}`,
      );
      return;
    }
    if (!choice) return;

    // Step 3: For non-Once, choose target path
    if (choice.scope !== "once") {
      try {
        const targets = filesystemTargetOptions(path, home, choice.scope);
        if (targets.length > 1) {
          const targetChoice = await chooseOption(
            `agent-sandbox: ${verb(action)} filesystem target?`,
            targets,
            ctx,
          );
          if (targetChoice) choice = targetChoice;
        }
      } catch (err) {
        ctx.ui.notify?.(
          `agent-sandbox: filesystem target prompt failed: ${(err as Error).message}`,
        );
        return;
      }
    }

    try {
      await submitDecision({ approve: action === "approve", id: req.id }, choice, req);
    } catch (err) {
      ctx.ui.notify?.(
        `agent-sandbox: filesystem ${verb(action)} failed: ${(err as Error).message}`,
      );
    }
  }
  // ---- Submit decision ----

  async function submitDecision(
    decision: { approve: boolean; id: string },
    choice: ScopeOption,
    reqCtx?: { cwd?: string; home?: string; project_root?: string },
  ): Promise<void> {
    const op = decision.approve ? "approve" : "deny";
    try {
      await sendPolicyRpc({
        op,
        id: decision.id,
        scope: choice.scope,
        ...(policySessionId ? { session_id: policySessionId } : {}),
        ...(choice.target ? { target: choice.target } : {}),
        ...rpcContext(reqCtx),
      });
    } catch (err) {
      const ctx = currentContext;
      ctx?.ui.notify?.(`agent-sandbox: ${op} failed: ${(err as Error).message}`);
    }
  }

  function connectPolicyUi(ctx: ExtensionContext): void {
    const path = process.env.AGENT_SANDBOX_POLICY_SOCKET ?? DEFAULT_SOCKET;
    uiSocket = net.createConnection(path);
    uiSocket.setEncoding("utf8");
    uiSocket.on("connect", () => {
      const registerReq = {
        op: "register_ui",
        ui_client: "omp",
        ...rpcContext(),
      };
      sendPolicyRpc(registerReq)
        .then((reply) => {
          if (reply.session_id && typeof reply.session_id === "string") {
            policySessionId = reply.session_id;
          }
        })
        .catch((err: Error) => {
          ctx.ui.notify?.(
            `agent-sandbox: register_ui failed: ${err.message}`,
          );
        });
    });

    uiSocket.on("error", (err: Error) => {
      ctx.ui.notify?.(
        `agent-sandbox: cannot connect to policy socket ${path}: ${err.message}`,
      );
    });

    setupSocketHandlers(ctx);
  }

  function setupSocketHandlers(ctx: ExtensionContext): void {
    if (!uiSocket) return;

    uiSocket.on("data", (chunk: string) => {
      const { rest, lines } = parseLines(lineBuf, chunk);
      lineBuf = rest;
      for (const line of lines) {
        try {
          const msg = JSON.parse(line) as PolicyMessage;
          onPolicyMessage(msg);
        } catch {
          // ignore malformed lines
        }
      }
    });

    uiSocket.on("close", () => {
      if (uiSocket) {
        ctx.ui.notify?.("agent-sandbox: policy UI connection closed");
        uiSocket = null;
        policySessionId = null;
        lineBuf = "";
      }
    });
  }

  // ---- Commands ----

  pi.registerCommand("sandbox approve", {
    description: "Approve a pending sandbox request by id",
    async handler(input: unknown) {
      const args = commandArgs(input);
      if (args.length < 1) return "Usage: /sandbox approve <id> [scope=once]";
      const id = args[0];
      const scope = (args[1] ?? "once") as ApprovalScope;
      await submitDecision(
        { approve: true, id },
        { label: scope, scope: scope as ApprovalScope },
      );
      return `Approved ${id}`;
    },
  });

  pi.registerCommand("sandbox deny", {
    description: "Deny a pending sandbox request by id",
    async handler(input: unknown) {
      const args = commandArgs(input);
      if (args.length < 1) return "Usage: /sandbox deny <id>";
      const id = args[0];
      await submitDecision(
        { approve: false, id },
        { label: "Once", scope: "once" },
      );
      return `Denied ${id}`;
    },
  });

  pi.registerCommand("sandbox reload", {
    description: "Reload sandbox policy from declarative config",
    async handler() {
      try {
        const reply = await sendPolicyRpc({ op: "reload", ...rpcContext() });
        return `Policy reloaded: ${JSON.stringify(reply)}`;
      } catch (err) {
        return `Reload failed: ${(err as Error).message}`;
      }
    },
  });

  pi.registerCommand("sandbox status", {
    description: "Show sandbox policy daemon status",
    async handler() {
      try {
        const reply = await sendPolicyRpc({ op: "status", ...rpcContext() });
        const r = reply as Record<string, unknown>;
        const lines: string[] = [];
        if (r.ui_connected !== undefined) {
          lines.push(`UI connected: ${r.ui_connected}`);
        }
        if (r.pending !== undefined) {
          const pending = r.pending as Array<Record<string, unknown>>;
          lines.push(`Pending: ${pending.length}`);
          for (const p of pending) {
            lines.push(`  ${JSON.stringify(p)}`);
          }
        }
        if (r.declarative_rules !== undefined) {
          lines.push(`Declarative rules: ${r.declarative_rules}`);
        }
        return lines.join("\n") || JSON.stringify(reply);
      } catch (err) {
        return `Status failed: ${(err as Error).message}`;
      }
    },
  });

  pi.registerCommand("sandbox disconnect", {
    description: "Disconnect and reconnect the policy UI",
    handler(_input: unknown, ctx: ExtensionContext) {
      disconnectPolicyUi();
      if (reconnectTimer) clearInterval(reconnectTimer);
      reconnectTimer = setInterval(() => {
        if (uiSocket) {
          clearInterval(reconnectTimer!);
          reconnectTimer = null;
          return;
        }
        connectPolicyUi(ctx);
      }, 2000);
      return "Disconnected; reconnecting...";
    },
  });

  // ---- Lifecycle ----

  pi.on("session_start", async (_event: unknown, ctx: ExtensionContext) => {
    currentContext = ctx;
    connectPolicyUi(ctx);
  });

  pi.on("session_shutdown", async () => {
    if (reconnectTimer) clearInterval(reconnectTimer);
    disconnectPolicyUi();
    currentContext = null;
  });
}
