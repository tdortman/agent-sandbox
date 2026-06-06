import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import * as net from "node:net";
import { policyRpc } from "./policy-client";

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

const NETWORK_APPROVAL_OPTIONS = [
  "Allow once (this connection only)",
  "Allow for this session",
  "Allow for this project",
  "Allow globally (user config)",
  "Deny once (this connection only)",
  "Deny for this session",
  "Deny for this project",
  "Deny globally (user config)",
] as const;

const SUDO_APPROVAL_OPTIONS = [
  "Allow once (this command only)",
  "Allow for this session",
  "Allow for this project",
  "Allow globally (user config)",
  "Deny once (this command only)",
  "Deny for this session",
  "Deny for this project",
  "Deny globally (user config)",
] as const;

const SCOPE_BY_LABEL: Record<string, string> = {
  "Allow once (this connection only)": "once",
  "Allow once (this command only)": "once",
  "Allow for this session": "session",
  "Allow for this project": "project",
  "Allow globally (user config)": "global",
  "Deny once (this connection only)": "once",
  "Deny once (this command only)": "once",
  "Deny for this session": "session",
  "Deny for this project": "project",
  "Deny globally (user config)": "global",
};

const DENY_LABELS = new Set(
  Object.keys(SCOPE_BY_LABEL).filter((k) => k.startsWith("Deny ")),
);

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
      },
    };
  }

  function socketPath(): string {
    return process.env.AGENT_SANDBOX_POLICY_SOCKET ?? DEFAULT_SOCKET;
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

  async function handleNetworkRequest(
    req: NetworkRequest,
    ctx: ExtensionContext,
  ): Promise<void> {
    const url = req.url ?? `${req.scheme ?? "https"}://${req.host}:${req.port}`;
    const choice = await ctx.ui.select(
      `agent-sandbox: allow ${url}?`,
      [...NETWORK_APPROVAL_OPTIONS],
    );
    if (!choice) return;

    const scope = SCOPE_BY_LABEL[choice];
    const rpcCtx = rpcContext(req);
    const sessionId = policySessionId;

    if (DENY_LABELS.has(choice)) {
      if (scope === "session" && !sessionId) {
        ctx.ui.notify?.(
          "agent-sandbox: session deny unavailable (policy UI not connected).",
        );
        return;
      }
      const resp = await policyRpc(
        {
          op: "deny",
          id: req.id,
          scope,
          ...(sessionId ? { session_id: sessionId } : {}),
          ...rpcCtx,
        },
        socketPath(),
      );
      if (!resp.ok) {
        ctx.ui.notify?.(
          `agent-sandbox: deny failed (${String(resp.error ?? "unknown")}).`,
        );
      } else if (scope === "project" && resp.path) {
        ctx.ui.notify?.(`Project policy saved to ${String(resp.path)}.`);
      }
      return;
    }

    if (scope === "session" && !sessionId) {
      ctx.ui.notify?.(
        "agent-sandbox: session approval unavailable (policy UI not connected).",
      );
      return;
    }

    const resp = await policyRpc(
      {
        op: "approve",
        id: req.id,
        scope,
        ...(sessionId ? { session_id: sessionId } : {}),
        ...rpcCtx,
      },
      socketPath(),
    );

    if (!resp.ok) {
      ctx.ui.notify?.(
        `agent-sandbox: approval failed (${String(resp.error ?? "unknown")}).`,
      );
      return;
    }

    if (scope === "project" && resp.path) {
      ctx.ui.notify?.(`Project policy saved to ${String(resp.path)}.`);
    }
  }

  function elevationPrompt(req: ElevationRequest): string {
    const cmd =
      req.argv.length > 0 ? `sudo ${req.argv.join(" ")}` : "sudo";
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
    const choice = await ctx.ui.select(elevationPrompt(req), [
      ...SUDO_APPROVAL_OPTIONS,
    ]);
    if (!choice) return;

    const scope = SCOPE_BY_LABEL[choice];
    const rpcCtx = rpcContext(req);
    const sessionId = policySessionId;

    if (DENY_LABELS.has(choice)) {
      if (scope === "session" && !sessionId) {
        ctx.ui.notify?.(
          "agent-sandbox: session deny unavailable (policy UI not connected).",
        );
        return;
      }
      const resp = await policyRpc(
        {
          op: "deny",
          id: req.id,
          scope,
          ...(sessionId ? { session_id: sessionId } : {}),
          ...rpcCtx,
        },
        socketPath(),
      );
      if (!resp.ok) {
        ctx.ui.notify?.(
          `agent-sandbox: elevation deny failed (${String(resp.error ?? "unknown")}).`,
        );
      } else if (scope === "project" && resp.path) {
        ctx.ui.notify?.(`Project policy saved to ${String(resp.path)}.`);
      }
      return;
    }

    if (scope === "session" && !sessionId) {
      ctx.ui.notify?.(
        "agent-sandbox: session approval unavailable (policy UI not connected).",
      );
      return;
    }

    const resp = await policyRpc(
      {
        op: "approve",
        id: req.id,
        scope,
        ...(sessionId ? { session_id: sessionId } : {}),
        ...rpcCtx,
      },
      socketPath(),
    );

    if (!resp.ok) {
      ctx.ui.notify?.(
        `agent-sandbox: elevation approval failed (${String(resp.error ?? "unknown")}).`,
      );
    } else if (scope === "project" && resp.path) {
      ctx.ui.notify?.(`Project policy saved to ${String(resp.path)}.`);
    }
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
