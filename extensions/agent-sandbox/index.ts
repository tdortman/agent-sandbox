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
  let uiConnectedAnnounced = false;
  const home = process.env.HOME ?? "";
  const projectRoot = process.env.AGENT_SANDBOX_PROJECT_ROOT ?? "";

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

  function socketPath(): string {
    return (
      process.env.AGENT_SANDBOX_POLICY_SOCKET ??
      DEFAULT_SOCKET
    );
  }

  function disconnectPolicyUi(): void {
    const socket = uiSocket;
    uiSocket = null;
    policySessionId = null;
    lineBuf = "";
    if (!socket) return;
    try {
      if (!socket.destroyed) {
        socket.write(`${JSON.stringify({ op: "unregister_ui" })}\n`);
      }
    } catch {
      // ignore
    }
    socket.destroy();
  }

  function approvalHostPatterns(host: string): string[] {
    const normalized = host.trim().toLowerCase().replace(/\.+$/, "");
    if (!normalized) return [];
    const labels = normalized.split(".");
    const patterns = [normalized];
    for (let index = 1; index < labels.length; index += 1) {
      const suffix = labels.slice(index).join(".");
      if (suffix.includes(".")) {
        patterns.push(`*.${suffix}`);
      }
    }
    return patterns;
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
  function scopeLabel(scope: ApprovalScope): string {
    switch (scope) {
      case "once":
        return "Once";
      case "session":
        return "This session";
      case "project":
        return "This project";
      case "global":
        return "Globally";
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
    const hosts = approvalHostPatterns(host);
    return hosts.map((candidate) => ({
      label: candidate,
      scope,
      target: { kind: "network_host" as const, host: candidate },
    }));
  }

  function notifyPrompt(ctx: ExtensionContext, title: string, body: string): void {
    const hasDisplay =
      process.env.DISPLAY !== undefined ||
      process.env.WAYLAND_DISPLAY !== undefined;
    if (!hasDisplay) return;
    const notifyBin =
      process.env.AGENT_SANDBOX_NOTIFY_SEND ?? "notify-send";
    execFile(
      notifyBin,
      [title, body],
      (err) => {
        if (err) {
          ctx.ui.notify?.(
            `agent-sandbox: notify-send failed (${err.message}); prompt still works via OMP.`,
          );
        }
      },
    );
  }
  function sudoScopeOptions(
    argv: string[],
    sessionAvailable: boolean,
  ): ScopeOption[] {
    const options: ScopeOption[] = [{ label: "This command only", scope: "once" }];
    const prefixes = sudoApprovalPrefixes(argv);
    const pushOptions = (scope: ApprovalScope) => {
      for (const prefix of prefixes) {
        options.push({
          label: `${scopeLabel(scope)} — ${formatSudoCommand(prefix)}`,
          scope,
          target: { kind: "sudo_command", argv: prefix },
        });
      }
    };
    if (sessionAvailable) {
      pushOptions("session");
    }
    pushOptions("project");
    pushOptions("global");
    return options;
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

  async function chooseScopeOption(
    title: string,
    options: ScopeOption[],
    ctx: ExtensionContext,
    opts?: { signal?: AbortSignal },
  ): Promise<ScopeOption | undefined> {
    const choice = await ctx.ui.select(
      title,
      options.map((option) => option.label),
      opts,
    );
    return options.find((option) => option.label === choice);
  }
  async function submitDecision(
    req: NetworkRequest | ElevationRequest,
    action: PromptAction,
    choice: ScopeOption,
    ctx: ExtensionContext,
  ): Promise<void> {
    const sessionId = policySessionId;
    if (choice.scope === "session" && !sessionId) {
      const noun = action === "approve" ? "approval" : "deny";
      ctx.ui.notify?.(
        `agent-sandbox: session ${noun} unavailable (policy UI not connected).`,
      );
      return;
    }
    const resp = await policyRpc(
      {
        op: action,
        id: req.id,
        scope: choice.scope,
        ...(sessionId ? { session_id: sessionId } : {}),
        ...(choice.target ? { target: choice.target } : {}),
        ...rpcContext(req),
      },
      socketPath(),
    );
    if (!resp.ok) {
      const err = String(resp.error ?? "unknown");
      const label =
        action === "approve"
          ? req.type === "elevation_request"
            ? "elevation approval"
            : "approval"
          : req.type === "elevation_request"
            ? "elevation deny"
            : "deny";
      ctx.ui.notify?.(
        `agent-sandbox: ${label} failed (${err}).`,
      );
      return;
    }
    const savedPath = resp.path ?? resp.policy_path;
    if (choice.scope === "project" && savedPath) {
      ctx.ui.notify?.(`Project policy saved to ${String(savedPath)}.`);
    }
  }

  async function handleNetworkRequest(
    req: NetworkRequest,
    ctx: ExtensionContext,
  ): Promise<void> {
    const url = req.url ?? `${req.scheme ?? "https"}://${req.host}:${req.port}`;
    notifyPrompt(
      ctx,
      "agent-sandbox: Network request",
      `Allow connection to ${url}?`,
    );

    // Step 1: choose action
    const action = await chooseAction(`agent-sandbox: ${url}`, ctx);
    if (!action) return;

    // Step 2: choose scope
    const scope = await chooseScopeOption(
      `agent-sandbox: ${action} ${url} scope?`,
      scopeOnlyOptions(policySessionId !== null),
      ctx,
    );
    if (!scope) return;

    // Step 3: for non-Once scopes, choose target level
    const target = scope.scope === "once"
      ? undefined
      : await chooseScopeOption(
          `agent-sandbox: ${action} ${url} target?`,
          networkTargetOptions(req.host, scope.scope),
          ctx,
        );
    if (scope.scope !== "once" && !target) return;

    const choice: ScopeOption = {
      label: "",
      scope: scope.scope,
      target: target?.target,
    };
    await submitDecision(req, action, choice, ctx);
  }

  function elevationPrompt(req: ElevationRequest): string {
    const cmd = formatSudoCommand(req.argv);
    const cwd = req.cwd?.trim();
    const lines = [cmd, "", "Allow this command to run as root on the host?"];
    if (cwd) {
      lines.push("", `Working directory:\n${cwd}`);
    }
    return lines.join("\n");
  }

  async function handleElevation(
    req: ElevationRequest,
    ctx: ExtensionContext,
  ): Promise<void> {
    const cmd = formatSudoCommand(req.argv);
    notifyPrompt(
      ctx,
      "agent-sandbox: Elevation request",
      `Allow "${cmd}" to run as root?`,
    );
    const action = await chooseAction(elevationPrompt(req), ctx);
    if (!action) return;
    const choice = await chooseScopeOption(
      `agent-sandbox: ${action} sudo scope?`,
      sudoScopeOptions(req.argv, policySessionId !== null),
      ctx,
    );
    if (!choice) return;
    await submitDecision(req, action, choice, ctx);
  }
  function onPolicyMessage(line: string, ctx: ExtensionContext): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return;
    }
    if (msg.type === "network_request") {
      void handleNetworkRequest(msg as NetworkRequest, ctx);
    } else if (msg.type === "elevation_request") {
      void handleElevation(msg as ElevationRequest, ctx);
    }
  }

  function stopPolicyUiReconnect(): void {
    if (reconnectTimer !== null) {
      clearInterval(reconnectTimer);
      reconnectTimer = null;
    }
  }

  async function connectPolicyUi(ctx: ExtensionContext): Promise<void> {
    if (uiSocket && !uiSocket.destroyed) return;

    disconnectPolicyUi();

    try {
      const socket = net.createConnection(socketPath());
      uiSocket = socket;

      await new Promise<void>((resolve, reject) => {
        socket.once("error", reject);
        socket.once("connect", () => resolve());
      });
      socket.setEncoding("utf8");
      socket.on("data", (chunk: string) => {
        const parsed = parseLines(lineBuf, chunk);
        lineBuf = parsed.rest;
        for (const line of parsed.lines) {
          onPolicyMessage(line, ctx);
        }
      });
      socket.on("close", () => {
        uiSocket = null;
        policySessionId = null;
        uiConnectedAnnounced = false;
      });

      const regCtx = rpcContext();
      socket.write(
        `${JSON.stringify({
          op: "register_ui",
          ui_client: "omp",
          ...regCtx,
        })}\n`,
      );
      const reg = await readOneJsonLine(socket);
      if (reg.ok && typeof reg.session_id === "string") {
        policySessionId = reg.session_id;
        if (!uiConnectedAnnounced) {
          ctx.ui.notify?.("agent-sandbox: policy UI connected.");
          uiConnectedAnnounced = true;
        }
      } else {
        ctx.ui.notify?.(
          `agent-sandbox: policy UI register failed (${String(reg.error ?? "no session_id")}).`,
        );
        disconnectPolicyUi();
      }
    } catch (err) {
      disconnectPolicyUi();
      if (!uiConnectedAnnounced) {
        ctx.ui.notify?.(
          `agent-sandbox: cannot connect to policyd (${String(err)}); retrying…`,
        );
      }
    }
  }

  function startPolicyUiReconnect(ctx: ExtensionContext): void {
    stopPolicyUiReconnect();
    void connectPolicyUi(ctx);
    reconnectTimer = setInterval(() => {
      void connectPolicyUi(ctx);
    }, 2000);
  }

  pi.on("session_start", async (_event, ctx) => {
    uiConnectedAnnounced = false;
    startPolicyUiReconnect(ctx);
  });

  pi.on("session_end", () => {
    stopPolicyUiReconnect();
    uiConnectedAnnounced = false;
    disconnectPolicyUi();
  });


  pi.registerCommand("sandbox", {
    description: "Agent sandbox policy status and reload",
    handler: async (args, ctx) => {
      const sub = (args[0] ?? "status").toLowerCase();
      const rpcCtx = rpcContext();
      try {
        if (sub === "reload") {
          const resp = await policyRpc(
            {
              op: "reload",
              ...rpcCtx,
            },
            socketPath(),
          );
          ctx.ui.notify?.(
            resp.ok ? "Policy reloaded." : `Reload failed: ${resp.error}`,
          );
          return;
        }
        const resp = await policyRpc(
          {
            op: "status",
            ...rpcCtx,
          },
          socketPath(),
        );
        const pending = (resp.pending as unknown[]) ?? [];
        const merged = resp.merged as { allow?: unknown[] } | undefined;
        const allow = merged?.allow ?? [];
        ctx.ui.notify?.(
          `Sandbox policy: ${allow.length} host rules, ${pending.length} pending.`,
        );
      } catch (err) {
        ctx.ui.notify?.(`agent-sandbox: ${String(err)}`);
      }
    },
  });
}
