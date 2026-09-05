#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { RelayClient, type RelayConfig } from "./relay.js";
import { RelayError } from "./security.js";
import { OperatorManager, defaultOperatorStatePath } from "./operator.js";

function configuration(): RelayConfig {
  const env = process.env;
  const rzUrl = env.RELAY_RENDEZVOUS_URL;
  const readKey = env.RELAY_RENDEZVOUS_READ_KEY;
  if (Boolean(rzUrl) !== Boolean(readKey)) throw new RelayError("set both rendezvous URL and read key; partial configuration is forbidden");
  const url = env.RELAY_URL;
  const token = env.RELAY_TOKEN;
  if (!rzUrl && Boolean(url) !== Boolean(token)) throw new RelayError("set both static URL and token");
  return {
    ...(rzUrl && readKey ? { rendezvous: { url: rzUrl, readKey } } : {}),
    ...(url && token ? { staticTarget: { url, token } } : {}),
    defaultTimeoutSeconds: Number(env.RELAY_AGENT_TIMEOUT_S ?? 30),
    ...(env.RELAY_HTTP_TIMEOUT_MS ? { httpTimeoutMs: Number(env.RELAY_HTTP_TIMEOUT_MS) } : {}),
  };
}

async function reply(action: () => Promise<string>) {
  try { return { content: [{ type: "text" as const, text: await action() }] }; }
  catch (error) {
    return {
      content: [{ type: "text" as const, text: `ERROR: ${error instanceof RelayError ? error.message : "relay request failed"}` }],
      isError: true,
    };
  }
}

async function main() {
  const config = configuration();
  const operator = config.rendezvous ? new OperatorManager(
    process.env.RELAY_OPERATOR_STATE ?? defaultOperatorStatePath(),
    config.rendezvous.url,
  ) : undefined;
  const client = new RelayClient(config, fetch, Date.now, operator);
  const server = new McpServer({ name: "relay-mcp", version: "0.6.0" });
  server.registerTool("current_target", {
    title: "Show relay target",
    description: "Discover the target automatically using the persistent package credential. Refuse an unexpected or replaced session. The reported host name is untrusted. Does not contact the target.",
    inputSchema: {},
  }, async () => reply(() => client.currentTarget()));
  server.registerTool("check_agent", {
    title: "Check relay agent",
    description: "Discover and check the relay agent automatically. The session must match the package prepared on the operator workstation; no manual pairing is needed.",
    inputSchema: {},
  }, async () => reply(() => client.checkAgent()));
  server.registerTool("run_command", {
    title: "Run command on verified relay target",
    description: "Automatically discover and authenticate the target from the prepared package, then run one shell command (cmd /c on Windows, sh -c on Unix). An unexpected or replaced session is refused. Each call is independent.",
    inputSchema: {
      command: z.string().min(1).max(64 << 10),
      timeout_seconds: z.number().int().min(1).max(3600).optional().describe("Command timeout in seconds; otherwise RELAY_AGENT_TIMEOUT_S, default 30"),
    },
  }, async ({ command, timeout_seconds }) => reply(() => client.runCommand(command, timeout_seconds)));
  await server.connect(new StdioServerTransport());
  process.stderr.write("relay-mcp connected\n");
}

main().catch(error => {
  process.stderr.write(`relay-mcp: ${error instanceof RelayError ? error.message : "startup failed"}\n`);
  process.exitCode = 1;
});
