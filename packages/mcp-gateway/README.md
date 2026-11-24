# `@oconnectortech/mcp-gateway` — ABS Core Sovereign MCP Firewall

[![npm](https://img.shields.io/npm/v/@oconnectortech/mcp-gateway)](https://www.npmjs.com/package/@oconnectortech/mcp-gateway)

Standalone, zero-config runtime governance and cryptographic non-repudiation firewall for **Model Context Protocol (MCP)** servers and AI agent tool calls.

- **SI-001 (Evidence Precedes Action):** seals SHA-256 hash-chained receipts **before** forwarding any tool call.
- **SI-004 (Fail-Closed Default):** blocks denied or escalated tools before they reach the upstream MCP server.
- **Standalone Distribution:** self-contained ESM bundle with zero private `workspace:*` runtime dependencies.

---

## 1. Transparent MCP `stdio` Firewall (`wrap`)

Place ABS Core directly in front of any MCP server in **Claude Desktop, Cursor, Windsurf, VS Code, or Claude Code** — zero code changes required:

```json
{
  "mcpServers": {
    "filesystem-guarded": {
      "command": "npx",
      "args": [
        "-y", "@oconnectortech/mcp-gateway@latest",
        "wrap", "--pack", "devsecops", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "."
      ]
    }
  }
}
```

Use `--shadow` to observe and log `SHADOW_DENY` receipts before turning on enforcement.

---

## 2. Built-in Regulatory Packs & Local Dashboard UI (`GET /ui`)

```bash
# Scaffold .abs/policy.json from built-in packs: devsecops | fintech-pix | lgpd-health
npx @oconnectortech/mcp-gateway init --pack devsecops

# Start local HTTP firewall (/v1/authorize) + visual dashboard (http://127.0.0.1:8787/ui)
npx @oconnectortech/mcp-gateway serve --port 8787
```

The built-in `/ui` dashboard provides live ALLOW / DENY / ESCALATE / SHADOW timelines, one-click human Approve/Reject escalation controls, and NDJSON audit export.

---

## 3. 1-Line Tool Guard for Vercel AI SDK & Node Agents

```ts
import { wrapTools } from '@oconnectortech/mcp-gateway';

const tools = wrapTools(
  {
    'fs.read': { execute: async ({ path }: { path: string }) => readFile(path) },
    'system.exec': async ({ cmd }: { cmd: string }) => runShell(cmd),
  },
  { pack: 'devsecops' }, // or { policy: fs.readFileSync('.abs/policy.json', 'utf8') }
);
```

---

## 4. Programmatic `AbsMcpGateway` API

```ts
import { AbsMcpGateway } from '@oconnectortech/mcp-gateway';

const gateway = new AbsMcpGateway({
  policy: JSON.stringify({
    id: 'my-policy',
    deny_tools: ['system.exec', 'fs.delete*'],
    escalate_tools: ['deploy.production*'],
  }),
  fullPipeline: false,
});

const decision = await gateway.interceptToolCall('tools/call', {
  name: 'system.exec',
  arguments: { cmd: 'rm -rf /' },
});

if (!decision.allowed) {
  throw new Error(`Blocked (${decision.decision}): ${decision.reason}`);
}
```

For full 11-gate QUORUM + Ed25519 OID verification (`fullPipeline: true`), sign the canonical intent produced by `createMcpGovernanceIntent(agentId, toolName, args, traceId)` with your agent's Ed25519 keypair.

---

## CLI Commands

```bash
npx @oconnectortech/mcp-gateway init [--pack devsecops|fintech-pix|lgpd-health]
npx @oconnectortech/mcp-gateway wrap [--shadow] [--pack <pack>] [--policy <path>] -- <cmd> [args...]
npx @oconnectortech/mcp-gateway serve [--port 8787] [--shadow] [--pack <pack>]
npx @oconnectortech/mcp-gateway scan
npx @oconnectortech/mcp-gateway watch --demo
npx @oconnectortech/mcp-gateway keys init
```

## License

MIT — [ABS Core Repository](https://github.com/eusheriff/abs-core-gateway)
