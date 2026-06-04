import * as net from "node:net";

export type PolicyRequest = Record<string, unknown>;
export type PolicyResponse = Record<string, unknown> & { ok?: boolean };
export type ApprovalScope = "once" | "session" | "project" | "global";

const DEFAULT_SOCKET = "/run/agent-sandbox/policy.sock";

export async function policyRpc(
  req: PolicyRequest,
  socketPath = process.env.AGENT_SANDBOX_POLICY_SOCKET ?? DEFAULT_SOCKET,
): Promise<PolicyResponse> {
  return await new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath);
    let buf = "";
    client.setEncoding("utf8");
    client.on("error", reject);
    client.on("connect", () => {
      client.write(`${JSON.stringify(req)}\n`);
    });
    client.on("data", (chunk) => {
      buf += chunk;
      const idx = buf.indexOf("\n");
      if (idx === -1) return;
      const line = buf.slice(0, idx);
      client.end();
      try {
        resolve(JSON.parse(line) as PolicyResponse);
      } catch (err) {
        reject(err);
      }
    });
  });
}
