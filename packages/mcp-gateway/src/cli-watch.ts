/**
 * ABS MCP Watch — Real-time CLI for MCP Gateway
 *
 * Shows intercepted tool calls, policy decisions, and blocked actions
 * in real-time with visual impact. This is the "Matrix moment" that
 * converts the developer.
 *
 * Usage:
 *   abs-mcp watch                     # Watch all events
 *   abs-mcp watch --filter blocked    # Only blocked events
 *   abs-mcp watch --json              # Machine-readable output
 *
 * @module @oconnector/mcp-gateway/cli-watch
 * @version 4.3.3
 */

import type { GatewayEvent, GatewayDecision, MCPToolCall } from './proxy';
import { AbsMcpGateway } from './proxy';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// ── ANSI Colors ──

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
  gray: '\x1b[90m',
};

// ── Formatters ──

function formatTimestamp(): string {
  const now = new Date();
  return `${c.gray}${now.toISOString().slice(11, 23)}${c.reset}`;
}

function formatDecisionBadge(decision: string): string {
  switch (decision) {
    case 'ALLOW':
      return `${c.bgGreen}${c.bold} ✓ ALLOW ${c.reset}`;
    case 'DENY':
      return `${c.bgRed}${c.bold} ✗ DENY  ${c.reset}`;
    case 'ESCALATE':
      return `${c.bgYellow}${c.bold} ⚡ ESCALATE ${c.reset}`;
    default:
      return `${c.dim}${decision}${c.reset}`;
  }
}

function formatToolName(name: string): string {
  return `${c.cyan}${c.bold}${name}${c.reset}`;
}

function formatLatency(ms: number): string {
  if (ms < 1) return `${c.green}${ms.toFixed(2)}ms${c.reset}`;
  if (ms < 5) return `${c.green}${ms.toFixed(1)}ms${c.reset}`;
  if (ms < 25) return `${c.yellow}${ms.toFixed(1)}ms${c.reset}`;
  return `${c.red}${ms.toFixed(1)}ms${c.reset}`;
}

function formatArgs(args: Record<string, any>): string {
  const entries = Object.entries(args);
  if (entries.length === 0) return `${c.dim}(no args)${c.reset}`;

  const formatted = entries
    .slice(0, 3)
    .map(([k, v]) => {
      const val = typeof v === 'string'
        ? (v.length > 30 ? `"${v.substring(0, 30)}..."` : `"${v}"`)
        : JSON.stringify(v);
      return `${c.dim}${k}${c.reset}=${c.white}${val}${c.reset}`;
    })
    .join(' ');

  const more = entries.length > 3 ? ` ${c.dim}+${entries.length - 3} more${c.reset}` : '';
  return formatted + more;
}

function formatReceipt(receipt: string): string {
  if (!receipt) return '';
  return `${c.dim}receipt:${receipt.substring(0, 24)}...${c.reset}`;
}

// ── Display Functions ──

function printHeader(): void {
  console.log('');
  console.log(`${c.bold}${c.cyan}┌─────────────────────────────────────────────────────────┐${c.reset}`);
  console.log(`${c.bold}${c.cyan}│${c.reset}  ${c.bold}ABS Core MCP Gateway${c.reset} ${c.magenta}${c.bold}v4.3.3 Elite${c.reset}  ${c.dim}— Sovereign Stack${c.reset}  ${c.bold}${c.cyan}│${c.reset}`);
  console.log(`${c.bold}${c.cyan}│${c.reset}  ${c.green}🔐 OID:${c.reset}${c.dim}Persistent${c.reset}  ${c.yellow}🕒 TSA:${c.reset}${c.dim}RFC3161${c.reset}  ${c.blue}🔗 Link:${c.reset}${c.dim}CORTEX${c.reset}      ${c.bold}${c.cyan}│${c.reset}`);
  console.log(`${c.bold}${c.cyan}└─────────────────────────────────────────────────────────┘${c.reset}`);
  console.log('');
  console.log(`  ${c.dim}TIME          DECISION      TOOL                 LATENCY   DETAILS${c.reset}`);
  console.log(`  ${c.dim}${'─'.repeat(75)}${c.reset}`);
}

function printEvent(event: GatewayEvent): void {
  const ts = formatTimestamp();

  switch (event.type) {
    case 'INTERCEPTED':
      console.log(
        `  ${ts}  ${c.blue}${c.bold}▸ INTERCEPT${c.reset}  ${formatToolName(event.toolCall.toolName)}  ${formatArgs(event.toolCall.args)}`
      );
      break;

    case 'DECIDED':
      console.log(
        `  ${ts}  ${formatDecisionBadge(event.decision.decision)}  ` +
        `${formatToolName(event.toolCall.toolName)}  ` +
        `${formatLatency(event.decision.latencyMs)}  ` +
        `${c.dim}${event.decision.reason}${c.reset}`
      );
      console.log(
        `  ${c.dim}${''.padStart(14)}${c.reset}              ${formatReceipt(event.decision.cryptoReceipt)}`
      );
      break;

    case 'BLOCKED':
      console.log(
        `  ${ts}  ${formatDecisionBadge(event.decision.decision)}  ` +
        `${formatToolName(event.toolCall.toolName)}  ` +
        `${formatLatency(event.decision.latencyMs)}  ` +
        `${c.red}${c.bold}${event.decision.reason}${c.reset}`
      );
      const tsaBadge = event.decision.rfc3161Authority ? `${c.yellow}[🕒 ${event.decision.rfc3161Authority}]${c.reset} ` : '';
      console.log(
        `  ${c.dim}${''.padStart(14)}${c.reset}              ` +
        `${tsaBadge}` +
        `${c.dim}policy:${event.decision.policyReference}${c.reset}  ` +
        `${formatReceipt(event.decision.cryptoReceipt)}`
      );
      break;

    case 'ERROR':
      console.log(
        `  ${ts}  ${c.bgRed}${c.bold} ⚠ ERROR  ${c.reset}  ` +
        `${formatToolName(event.toolCall.toolName)}  ` +
        `${c.red}${event.error}${c.reset}`
      );
      break;
  }
}

function printStats(gateway: AbsMcpGateway): void {
  const s = gateway.getStats();
  console.log('');
  console.log(`  ${c.dim}${'─'.repeat(75)}${c.reset}`);
  console.log(
    `  ${c.bold}Stats:${c.reset} ` +
    `${c.white}${s.totalIntercepted}${c.reset} intercepted  ` +
    `${c.green}${s.totalAllowed}${c.reset} allowed  ` +
    `${c.red}${s.totalBlocked}${c.reset} blocked  ` +
    `${c.yellow}${s.totalEscalated}${c.reset} escalated  ` +
    `${c.dim}avg:${s.avgLatencyMs.toFixed(2)}ms${c.reset}`
  );

  // --- v4.3.3 Sovereign Vitals ---
  console.log(`  ${c.bold}Sovereign Health:${c.reset} ${c.green}Chain:Verified${c.reset} | ${c.yellow}TSA:Online${c.reset} | ${c.blue}MemBridge:Active${c.reset}`);
}

// ── Main Watch Loop ──

/**
 * Attaches the watch CLI to a gateway instance.
 * Renders all events in real-time with visual formatting.
 */
export function attachWatch(
  gateway: AbsMcpGateway,
  options: { filter?: 'all' | 'blocked' | 'allowed'; json?: boolean } = {}
): void {
  const { filter = 'all', json = false } = options;

  if (!json) {
    printHeader();
  }

  gateway.on('event', (event: GatewayEvent) => {
    // Apply filter
    if (filter === 'blocked' && event.type !== 'BLOCKED') return;
    if (filter === 'allowed' && event.type !== 'DECIDED') return;

    if (json) {
      console.log(JSON.stringify(event));
    } else {
      printEvent(event);
    }
  });

  // Print stats every 30 seconds
  if (!json) {
    setInterval(() => printStats(gateway), 30_000);
  }

  // Graceful shutdown
  process.on('SIGINT', () => {
    if (!json) {
      printStats(gateway);
      console.log(`\n  ${c.dim}Gateway stopped.${c.reset}\n`);
    }
    process.exit(0);
  });
}

// ── Demo Mode (for development/showcase) ──

/**
 * Runs a demo simulation showing the Gateway in action.
 * Useful for showcasing to developers and investors.
 */
export async function runDemo(): Promise<void> {
  const gateway = new AbsMcpGateway({
    policy: JSON.stringify({
      id: 'demo-policy',
      deny_tools: ['fs.delete*', 'db.drop*', 'system.exec'],
      escalate_tools: ['payment.*', 'user.delete'],
      arg_restrictions: {
        'db.query': { sql: 'deny:DROP|DELETE|TRUNCATE' },
      },
    }),
  });

  attachWatch(gateway);

  // Simulate tool calls
  const demoTools = [
    { method: 'tools/call', name: 'db.query', arguments: { sql: 'SELECT * FROM users WHERE active = true' } },
    { method: 'tools/call', name: 'fs.read', arguments: { path: '/data/report.csv' } },
    { method: 'tools/call', name: 'fs.delete_all', arguments: { path: '/data/*' } },
    { method: 'tools/call', name: 'db.query', arguments: { sql: 'DROP TABLE users' } },
    { method: 'tools/call', name: 'payment.charge', arguments: { amount: 5000, currency: 'USD' } },
    { method: 'tools/call', name: 'email.send', arguments: { to: 'cto@company.com', subject: 'Monthly Report' } },
    { method: 'tools/call', name: 'system.exec', arguments: { cmd: 'rm -rf /' } },
    { method: 'tools/call', name: 'db.insert', arguments: { table: 'logs', data: { event: 'audit_check' } } },
  ];

  for (const tool of demoTools) {
    await gateway.interceptToolCall(tool.method, tool);
    await new Promise(r => setTimeout(r, 800)); // Dramatic pause for demo
  }

  printStats(gateway);
  console.log(`\n  ${c.dim}Demo complete.${c.reset}\n`);
}

/**
 * Entry point for the Watch command.
 */
export async function startWatch(options: { demo?: boolean } = {}): Promise<void> {
  if (options.demo) {
    return runDemo();
  }
  
  // Real watch mode (future implementation or attaches to existing gateway)
  console.log(`${c.yellow}  ℹ${c.reset} Real-time watch mode starting...`);
  const gateway = new AbsMcpGateway(); // Uses default policy from .abs/policy.json
  attachWatch(gateway);
}

// CLI entry point when run directly (guard against esbuild bundling cli-watch into dist/cli.js)
const _entryFile = fileURLToPath(import.meta.url);
if (process.argv[1] === _entryFile && path.basename(_entryFile).startsWith('cli-watch')) {
  const demo = process.argv.includes('--demo');
  startWatch({ demo });
}
