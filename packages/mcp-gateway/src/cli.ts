#!/usr/bin/env node

/**
 * ABS Core CLI — Zero-friction onboarding for AI governance.
 *
 * Commands:
 *   abs-core init          → Scaffold governance config in current project
 *   abs-core watch         → Real-time MCP Gateway monitor
 *   abs-core verify <file> → Verify a SAR JSON file integrity
 *   abs-core export        → Generate compliance report from ledger
 *   abs-core keys init     → Generate Ed25519 signing key pair
 *   abs-core keys show     → Show current key fingerprint
 *
 * Usage:
 *   npx @oconnectortech/mcp-gateway init
 *   npx @oconnectortech/mcp-gateway watch --demo
 *
 * @module @oconnectortech/mcp-gateway/cli
 * @version 4.0.0
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as http from 'node:http';
import { startWatch } from './cli-watch';
import { AbsMcpGateway } from './proxy';
import { runSovereignScan, printScanResults } from './scanner';
import { resolvePolicyPack, listPolicyPackNames } from './policy-packs';
import { loadWrapPolicy, runStdioWrap } from './stdio-wrap';
import { renderDashboardHtml } from './dashboard-ui';
import { runRedTeamBenchmark } from './redteam';


// ── ANSI Colors ──
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  magenta: '\x1b[35m',
};

// ── Banner ──
function printBanner(): void {
  console.log(`
${c.bold}${c.blue}    ╔═══════════════════════════════════════╗
    ║${c.cyan}  🔐 ABS Core — Sovereign Accountability ${c.blue}║
    ║${c.dim}     Non-Repudiation as a Service        ${c.reset}${c.bold}${c.blue}║
    ╚═══════════════════════════════════════╝${c.reset}
  `);
}

// ── Init Command ──
function cmdInit(args: string[] = []): void {
  printBanner();
  console.log(`${c.cyan}Initializing ABS Core governance in current project...${c.reset}\n`);

  const cwd = process.cwd();
  const packIdx = args.indexOf('--pack');
  const packName = packIdx !== -1 ? args[packIdx + 1] : undefined;
  const force = args.includes('--force');

  // 1. Create .abs directory
  const absDir = path.join(cwd, '.abs');
  if (!fs.existsSync(absDir)) {
    fs.mkdirSync(absDir, { recursive: true });
    console.log(`${c.green}  ✓${c.reset} Created ${c.dim}.abs/${c.reset} directory`);
  }

  // 2. Create default or selected pack policy
  const policyPath = path.join(absDir, 'policy.json');
  if (!fs.existsSync(policyPath) || force) {
    let policyObj: Record<string, unknown>;
    if (packName) {
      const pack = resolvePolicyPack(packName);
      if (!pack) {
        console.error(`${c.red}  ✗${c.reset} Unknown pack "${packName}". Available packs: ${listPolicyPackNames().join(', ')}`);
        process.exit(1);
      }
      policyObj = { ...pack };
    } else {
      policyObj = {
        $schema: 'https://abscore.app/schemas/policy-v4.json',
        version: '6.1.0',
        description: 'ABS Core governance policy — edit to match your security requirements',
        deny_tools: [
          'system.exec',
          'system.shell',
          'fs.delete*',
          'fs.rmdir*',
          'db.drop*',
        ],
        escalate_tools: [
          'payment.*',
          'email.send',
          'api.deploy*',
        ],
        arg_restrictions: {
          'db.query': {
            sql: 'deny:DROP|DELETE|TRUNCATE|ALTER',
          },
          'fs.write': {
            path: 'deny:/etc|/sys|/proc|../',
          },
        },
        fail_mode: 'closed',
        require_oid: true,
        rfc3161: {
          enabled: true,
          primary: 'https://freetsa.org/tsr',
          fallback: 'https://timestamp.digicert.com',
        },
      };
    }

    fs.writeFileSync(policyPath, JSON.stringify(policyObj, null, 2));
    console.log(
      `${c.green}  ✓${c.reset} Created ${c.dim}.abs/policy.json${c.reset} — ${packName ? `pack "${packName}"` : 'default governance policy'}`,
    );
  } else {
    console.log(`${c.yellow}  ⚠${c.reset} ${c.dim}.abs/policy.json${c.reset} already exists — skipping (use --force to overwrite)`);
  }

  // 3. Create .env.example
  const envExamplePath = path.join(absDir, '.env.example');
  if (!fs.existsSync(envExamplePath)) {
    const envExample = `# ABS Core — Environment Variables
# Copy to .env and fill in values

# Ed25519 Signing Keys (Base64 DER format)
# Generate with: npx @oconnectortech/mcp-gateway keys init
ABS_SIGNING_KEY=
ABS_PUBLIC_KEY=

# Or PEM format (use \\n for newlines)
# ABS_SIGNING_KEY_PEM=
# ABS_PUBLIC_KEY_PEM=

# RFC 3161 Timestamp Authority (optional — defaults included)
# ABS_TSA_PRIMARY=https://freetsa.org/tsr
# ABS_TSA_FALLBACK=https://timestamp.digicert.com

# Ledger Database (optional — defaults to .abs/ledger.db)
# ABS_LEDGER_PATH=.abs/ledger.db

# Compliance Report Org Name
# ABS_ORG_NAME=YourCompany
`;
    fs.writeFileSync(envExamplePath, envExample);
    console.log(`${c.green}  ✓${c.reset} Created ${c.dim}.abs/.env.example${c.reset} — environment template`);
  }

  // 4. Update .gitignore
  const gitignorePath = path.join(cwd, '.gitignore');
  const absIgnoreLines = [
    '',
    '# ABS Core — Sensitive data',
    '.abs/*.pem',
    '.abs/*.db',
    '.abs/.env',
    '.abs/backups/',
  ];

  if (fs.existsSync(gitignorePath)) {
    const existing = fs.readFileSync(gitignorePath, 'utf-8');
    if (!existing.includes('.abs/*.pem')) {
      fs.appendFileSync(gitignorePath, absIgnoreLines.join('\n') + '\n');
      console.log(`${c.green}  ✓${c.reset} Updated ${c.dim}.gitignore${c.reset} — added .abs exclusions`);
    }
  } else {
    fs.writeFileSync(gitignorePath, absIgnoreLines.join('\n') + '\n');
    console.log(`${c.green}  ✓${c.reset} Created ${c.dim}.gitignore${c.reset} — with .abs exclusions`);
  }

  // 5. Create integration example
  const examplePath = path.join(absDir, 'example-integration.ts');
  if (!fs.existsSync(examplePath)) {
    const example = `/**
 * ABS Core — Quick Integration Example
 *
 * This shows how to wrap your MCP server with ABS Core governance.
 * Every tool call will be intercepted, evaluated, and logged.
 */

import { AbsMcpGateway } from '@oconnectortech/mcp-gateway';
import * as fs from 'fs';

// Load your policy
const policy = fs.readFileSync('.abs/policy.json', 'utf-8');

// Create the gateway
const gateway = new AbsMcpGateway({ policy });

// Listen for governance events (optional — for monitoring)
gateway.on('decision', (event) => {
  console.log(\`[\${event.decision}] \${event.toolName} — \${event.reason}\`);
});

// Intercept a tool call
async function governedToolCall(toolName: string, args: any) {
  const result = await gateway.interceptToolCall('tools/call', {
    name: toolName,
    arguments: args,
  });

  if (result.decision === 'DENY') {
    throw new Error(\`Blocked by ABS Core: \${result.reason}\`);
  }

  if (result.decision === 'ESCALATE') {
    console.warn(\` [WARNING]  Escalated: \${result.reason} — requires human approval\`);
    // In production: send to approval queue
    return null;
  }

  // ALLOW — proceed with the tool call
  return executeToolCall(toolName, args);
}

function executeToolCall(name: string, args: any) {
  // Your actual tool implementation here
  return { success: true, tool: name };
}

// Example usage
governedToolCall('db.query', { sql: 'SELECT * FROM users' });
governedToolCall('system.exec', { cmd: 'rm -rf /' }); // → DENIED
`;
    fs.writeFileSync(examplePath, example);
    console.log(`${c.green}  ✓${c.reset} Created ${c.dim}.abs/example-integration.ts${c.reset} — quick start code`);
  }

  // Summary
  console.log(`
${c.bold}${c.green}Done!${c.reset} ABS Core is ready. Next steps:

  ${c.cyan}1.${c.reset} Edit ${c.dim}.abs/policy.json${c.reset} to match your security requirements
  ${c.cyan}2.${c.reset} Generate signing keys:  ${c.bold}npx @oconnectortech/mcp-gateway keys init${c.reset}
  ${c.cyan}3.${c.reset} See example:            ${c.dim}.abs/example-integration.ts${c.reset}
  ${c.cyan}4.${c.reset} Monitor in real-time:   ${c.bold}npx @oconnectortech/mcp-gateway watch --demo${c.reset}

  ${c.dim}Docs: https://docs.abscore.app${c.reset}
  ${c.dim}Policy schema: https://abscore.app/schemas/policy-v4.json${c.reset}
`);
}

// ── Keys Command (Zero-dependency Node WebCrypto/crypto Ed25519) ──
async function cmdKeysInit(): Promise<void> {
  printBanner();
  console.log(`${c.cyan}Generating Ed25519 signing key pair...${c.reset}\n`);

  const keyDir = path.join(process.cwd(), '.abs');
  fs.mkdirSync(keyDir, { recursive: true });
  const privPath = path.join(keyDir, 'abs-signing-key.pem');
  const pubPath = path.join(keyDir, 'abs-public-key.pem');

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    const pubPem = fs.readFileSync(pubPath, 'utf8');
    const fp = crypto.createHash('sha256').update(pubPem).digest('hex');
    console.log(`${c.yellow}  ⚠${c.reset} Keys already exist in ${c.dim}.abs/${c.reset}`);
    console.log(`  Fingerprint: ${c.bold}${fp.substring(0, 32)}...${c.reset}`);
    console.log(`\n  ${c.dim}To regenerate, delete .abs/abs-signing-key.pem first.${c.reset}`);
    return;
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  fs.writeFileSync(privPath, privPem, { mode: 0o600 });
  fs.writeFileSync(pubPath, pubPem, { mode: 0o644 });
  const fp = crypto.createHash('sha256').update(pubPem).digest('hex');

  console.log(`${c.green}  ✓${c.reset} Keys generated and stored in ${c.dim}.abs/${c.reset}`);
  console.log(`  Fingerprint: ${c.bold}${fp.substring(0, 32)}...${c.reset}`);
  console.log(`\n  ${c.red}⚠ IMPORTANT:${c.reset} Back up ${c.dim}.abs/abs-signing-key.pem${c.reset} securely.`);
}

async function cmdKeysShow(): Promise<void> {
  const pubPath = path.join(process.cwd(), '.abs', 'abs-public-key.pem');
  if (!fs.existsSync(pubPath)) {
    console.log(
      `${c.red}  ✗${c.reset} No keys found. Run: ${c.bold}npx @oconnectortech/mcp-gateway keys init${c.reset}`
    );
    process.exit(1);
  }
  const pubPem = fs.readFileSync(pubPath, 'utf8');
  const fp = crypto.createHash('sha256').update(pubPem).digest('hex');
  console.log(`  Fingerprint: ${c.bold}${fp}${c.reset}`);
  console.log(`  Source:       ${c.dim}.abs/abs-public-key.pem${c.reset}`);
}

async function cmdServe(args: string[]): Promise<void> {
  const portIdx = args.indexOf('--port');
  const port = portIdx !== -1 ? Number(args[portIdx + 1]) : Number(process.env.ABS_GATEWAY_PORT ?? 8787);
  const isShadow = args.includes('--shadow') || process.env.ABS_GATEWAY_MODE === 'shadow';
  const packIdx = args.indexOf('--pack');
  const packName = packIdx !== -1 ? args[packIdx + 1] : undefined;
  const policyFile = path.resolve(process.cwd(), '.abs/policy.json');
  let rawPolicy: string;
  if (packName) {
    const pack = resolvePolicyPack(packName);
    if (!pack) {
      throw new Error(`Unknown pack "${packName}". Available: ${listPolicyPackNames().join(', ')}`);
    }
    rawPolicy = JSON.stringify(pack);
  } else {
    rawPolicy = fs.existsSync(policyFile)
      ? fs.readFileSync(policyFile, 'utf8')
      : JSON.stringify({ id: 'standalone-default', deny_tools: ['system.exec', 'system.shell', 'fs.delete*', 'db.drop*'], escalate_tools: ['deploy.production*', 'payment.*'] });
  }
  const auditFile = path.resolve(process.cwd(), '.abs/universal-gateway.ndjson');
  fs.mkdirSync(path.dirname(auditFile), { recursive: true });
  const resolutions = new Map<string, string>();

  const gw = new AbsMcpGateway({ policy: rawPolicy, fullPipeline: false });
  const srv = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
    if (req.method === 'GET' && url.pathname === '/health') {
      const body = JSON.stringify({ status: 'ok', service: 'abs-mcp-gateway-standalone', mode: isShadow ? 'shadow' : 'enforce', ui: `http://127.0.0.1:${port}/ui` });
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(body);
    }
    if (req.method === 'GET' && (url.pathname === '/ui' || url.pathname === '/')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(renderDashboardHtml(isShadow ? 'shadow' : 'enforce'));
    }
    if (req.method === 'GET' && url.pathname === '/v1/audit') {
      const lines = fs.existsSync(auditFile)
        ? fs.readFileSync(auditFile, 'utf8').split('\n').filter(Boolean)
        : [];
      const records = lines.map((line) => {
        try {
          const parsed = JSON.parse(line);
          if (parsed.trace_id && resolutions.has(parsed.trace_id)) {
            parsed.human_resolution = resolutions.get(parsed.trace_id);
          }
          return parsed;
        } catch {
          return null;
        }
      }).filter(Boolean);
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ count: records.length, records }));
    }
    if (req.method === 'POST' && url.pathname.startsWith('/v1/escalations/') && url.pathname.endsWith('/resolve')) {
      const traceId = decodeURIComponent(url.pathname.slice('/v1/escalations/'.length, -'/resolve'.length));
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      const resolution = body.resolution === 'APPROVED' ? 'APPROVED' : 'REJECTED';
      resolutions.set(traceId, resolution);
      const resolutionRecord = { schema: 'abs-human-resolution/v1', trace_id: traceId, resolution, recorded_at: new Date().toISOString() };
      fs.appendFileSync(auditFile, JSON.stringify(resolutionRecord) + '\n', { mode: 0o600 });
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(resolutionRecord));
    }
    if (req.method === 'POST' && url.pathname === '/v1/authorize') {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
      const payload = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
      const tool = String(payload.tool || payload.action || '');
      const toolArgs = payload.args && typeof payload.args === 'object' ? payload.args : {};
      const raw = await gw.interceptToolCall('tools/call', { name: tool, arguments: toolArgs });
      const wouldBlock = !raw.allowed || raw.decision === 'DENY' || raw.decision === 'ESCALATE';
      const decision = isShadow
        ? { ...raw, allowed: true, decision: wouldBlock ? 'SHADOW_DENY' : 'SHADOW_ALLOW', mode: 'shadow', would_block: wouldBlock, shadow_reason: wouldBlock ? raw.reason : undefined }
        : raw;
      const record = { schema: 'abs-universal-gateway-decision/v1', tenant_id: payload.tenant_id || 'default-tenant', trace_id: payload.trace_id || crypto.randomUUID(), tool, mode: isShadow ? 'shadow' : 'enforce', decision, recorded_at: new Date().toISOString() };
      fs.appendFileSync(auditFile, JSON.stringify(record) + '\n', { mode: 0o600 });
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(record));
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  });
  srv.listen(port, '127.0.0.1', () => {
    console.log(`${c.green}✓ ABS Core Standalone Gateway listening on http://127.0.0.1:${port} (mode: ${isShadow ? 'shadow' : 'enforce'})${c.reset}`);
    console.log(`${c.cyan}  Dashboard UI:${c.reset} http://127.0.0.1:${port}/ui`);
  });
}

async function cmdWrap(args: string[]): Promise<void> {
  const opts = loadWrapPolicy(args, process.cwd());
  const code = await runStdioWrap(opts);
  process.exit(code);
}

async function cmdRedteam(args: string[]): Promise<void> {
  const jsonMode = args.includes('--json');
  const report = await runRedTeamBenchmark();
  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.passed === report.total ? 0 : 1);
  }
  printBanner();
  console.log(`${c.bold}ABS Core — Reproducible Agentic Red-Team Scorecard${c.reset}\n`);
  for (const r of report.results) {
    const icon = r.passed ? `${c.green}✓${c.reset}` : `${c.red}✗${c.reset}`;
    const badge = r.actual === 'DENY' ? `${c.red}DENY${c.reset}` : `${c.yellow}${r.actual}${c.reset}`;
    console.log(`  ${icon} ${c.dim}${r.id}${c.reset}  ${badge.padEnd(18)} ${r.label} ${c.dim}(${r.pack} · ${r.latencyMs}ms)${c.reset}`);
  }
  console.log(`\n${c.bold}Score:${c.reset}   ${c.green}${report.passed}/${report.total} interdicted${c.reset}  |  ${c.bold}P50:${c.reset} ${report.p50Ms}ms  |  ${c.bold}P99:${c.reset} ${report.p99Ms}ms`);
  console.log(`${c.bold}Receipt:${c.reset} ${c.dim}sha256:${report.scorecardHash}${c.reset}\n`);
  process.exit(report.passed === report.total ? 0 : 1);
}

// ── Watch Command (delegate to cli-watch.ts) ──
async function cmdWatch(args: string[]): Promise<void> {
  const demo = args.includes('--demo');
  startWatch({ demo });
}

async function cmdScan(): Promise<void> {
  printBanner();
  console.log(`${c.cyan}Starting Real-Time Sovereign Audit Scan...${c.reset}`);
  console.log(`${c.dim}Checking local project for AI governance vulnerabilities...${c.reset}\n`);

  const results = await runSovereignScan(process.cwd());
  printScanResults(results);
}


// ── Main Router ──
async function startThreatIntelSync(): Promise<void> {
  const pollMs = parseInt(process.env.THREAT_INTEL_POLL_MS ?? '3600000', 10);
  if (pollMs === 0 || process.env.THREAT_INTEL_ENABLED === 'false') return;

  try {
    const modName = '@abs-core/threat-intel';
    const { ThreatIntelEngine } = await import(modName);
    const mythosPath = process.env.ABS_MYTHOS_PATTERNS_PATH
      ?? path.resolve(process.cwd(), 'modules/adversarial-analysis/mythos-patterns.yaml');
    const engine = new ThreatIntelEngine({
      mythosYamlPath: mythosPath,
      policyFeedbackEnabled: process.env.ABS_POLICY_FEEDBACK_ENABLED === '1',
    });
    // Initial sync on startup
    engine.sync().catch((e: Error) => console.warn('[ThreatIntel] Initial sync failed:', e.message));
    // Periodic sync
    if (pollMs > 0) engine.startPeriodicSync(pollMs);
    console.info(`[ThreatIntel] Live feed active (poll=${pollMs / 1000}s)`);
  } catch (e: any) {
    if (process.env.DEBUG) {
      console.warn('[ThreatIntel] Could not start sync (air-gap mode?):', e.message);
    }
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  // Start threat intel sync only for active daemon/proxy commands
  if (command === 'watch' || command === 'serve') {
    startThreatIntelSync().catch(() => {});
  }

  switch (command) {
    case 'init':
      cmdInit(args.slice(1));
      break;
    case 'scan':
      await cmdScan();
      break;
    case 'wrap':
      await cmdWrap(args.slice(1));
      break;
    case 'redteam':
      await cmdRedteam(args.slice(1));
      break;
    case 'serve':
      await cmdServe(args.slice(1));
      break;
    case 'watch':
      await cmdWatch(args.slice(1));
      break;
    case 'keys':
      if (args[1] === 'init') await cmdKeysInit();
      else if (args[1] === 'show') await cmdKeysShow();
      else {
        console.log(`Usage: abs-core keys [init|show]`);
      }
      break;
    case '--help':
    case '-h':
    case undefined:
      printBanner();
      console.log(`${c.bold}Commands:${c.reset}
  ${c.cyan}init${c.reset}          Scaffold governance config ${c.dim}(--pack devsecops|fintech-pix|lgpd-health)${c.reset}
  ${c.cyan}wrap${c.reset}          Transparent MCP stdio firewall ${c.dim}(wrap [--shadow] -- <mcp-server>)${c.reset}
  ${c.cyan}serve${c.reset}         Start standalone HTTP firewall + Dashboard UI ${c.dim}(--port 8787 --shadow)${c.reset}
  ${c.cyan}redteam${c.reset}       Run 10-vector local Agentic Red-Team benchmark ${c.dim}(--json)${c.reset}
  ${c.cyan}scan${c.reset}          Real-time project governance audit (Vulnerability check)
  ${c.cyan}watch${c.reset}         Real-time MCP Gateway monitor ${c.dim}(--demo for simulation)${c.reset}
  ${c.cyan}keys init${c.reset}     Generate Ed25519 signing key pair
  ${c.cyan}keys show${c.reset}     Show current key fingerprint

${c.bold}Examples:${c.reset}
  ${c.dim}$ npx @oconnectortech/mcp-gateway init --pack devsecops${c.reset}
  ${c.dim}$ npx @oconnectortech/mcp-gateway wrap -- npx -y @modelcontextprotocol/server-filesystem .${c.reset}
  ${c.dim}$ npx @oconnectortech/mcp-gateway serve --port 8787${c.reset}
  ${c.dim}$ npx @oconnectortech/mcp-gateway scan${c.reset}
  ${c.dim}$ npx @oconnectortech/mcp-gateway watch --demo${c.reset}
`);
      break;
    default:
      console.log(`${c.red}Unknown command: ${command}${c.reset}`);
      console.log(`Run ${c.bold}npx @oconnectortech/mcp-gateway --help${c.reset} for usage.`);
      process.exit(1);
  }
}

main().catch(err => {
  console.error(`${c.red}Fatal:${c.reset}`, err.message);
  process.exit(1);
});
