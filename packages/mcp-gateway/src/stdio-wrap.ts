/**
 * Transparent MCP JSON-RPC stdio proxy (`npx @oconnectortech/mcp-gateway wrap -- <cmd> [args...]`).
 *
 * Intercepts `tools/call` requests from any MCP client (Claude Desktop, Cursor,
 * Windsurf, Claude Code, VS Code) BEFORE forwarding to the target MCP server.
 *
 * Invariants enforced:
 * - SI-001 (Evidence Precedes Action): hash-chained receipt is sealed to disk
 *   before forwarding any tool call to the child server.
 * - SI-004 (Fail-Closed Default): invalid JSON-RPC tool calls or policy denials
 *   are blocked in enforce mode and never reach the child process.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { spawn } from 'node:child_process';
import { AbsMcpGateway } from './proxy';
import { resolvePolicyPack } from './policy-packs';

export interface StdioWrapOptions {
  command: string;
  commandArgs: string[];
  policyJson: string;
  shadow?: boolean;
  auditPath?: string;
}

export interface WrapReceipt {
  schema: 'abs-mcp-wrap-receipt/v1';
  recorded_at: string;
  tool: string;
  mode: 'enforce' | 'shadow';
  decision: string;
  allowed: boolean;
  would_block: boolean;
  reason: string;
  policy_reference: string;
  latency_ms: number;
  prev_hash: string;
  receipt_hash: string;
}

function appendHashChainedReceipt(
  auditFile: string,
  prevHash: string,
  entry: Omit<WrapReceipt, 'prev_hash' | 'receipt_hash'>,
): WrapReceipt {
  const payload = JSON.stringify({ ...entry, prev_hash: prevHash });
  const receiptHash = crypto.createHash('sha256').update(payload).digest('hex');
  const receipt: WrapReceipt = { ...entry, prev_hash: prevHash, receipt_hash: receiptHash };
  fs.mkdirSync(path.dirname(auditFile), { recursive: true });
  fs.appendFileSync(auditFile, JSON.stringify(receipt) + '\n', { mode: 0o600 });
  return receipt;
}

export function loadWrapPolicy(args: string[], cwd: string): {
  policyJson: string;
  shadow: boolean;
  auditPath: string;
  command: string;
  commandArgs: string[];
} {
  const sepIdx = args.indexOf('--');
  const flagArgs = sepIdx === -1 ? args : args.slice(0, sepIdx);
  const targetArgs = sepIdx === -1 ? [] : args.slice(sepIdx + 1);

  if (targetArgs.length === 0) {
    throw new Error(
      'Missing target MCP server command. Usage: npx @oconnectortech/mcp-gateway wrap [--shadow] [--pack devsecops] [--policy .abs/policy.json] -- <command> [args...]',
    );
  }

  const shadow = flagArgs.includes('--shadow') || process.env.ABS_GATEWAY_MODE === 'shadow';
  const packIdx = flagArgs.indexOf('--pack');
  const policyIdx = flagArgs.indexOf('--policy');
  const auditIdx = flagArgs.indexOf('--audit');

  let policyJson: string;
  if (policyIdx !== -1 && flagArgs[policyIdx + 1]) {
    const p = path.resolve(cwd, flagArgs[policyIdx + 1]);
    policyJson = fs.readFileSync(p, 'utf8');
  } else if (packIdx !== -1 && flagArgs[packIdx + 1]) {
    const pack = resolvePolicyPack(flagArgs[packIdx + 1]);
    if (!pack) {
      throw new Error(`Unknown policy pack "${flagArgs[packIdx + 1]}". Available: devsecops, fintech-pix, lgpd-health`);
    }
    policyJson = JSON.stringify(pack);
  } else {
    const defaultPolicyPath = path.resolve(cwd, '.abs/policy.json');
    policyJson = fs.existsSync(defaultPolicyPath)
      ? fs.readFileSync(defaultPolicyPath, 'utf8')
      : JSON.stringify(resolvePolicyPack('devsecops'));
  }

  const auditPath =
    auditIdx !== -1 && flagArgs[auditIdx + 1]
      ? path.resolve(cwd, flagArgs[auditIdx + 1])
      : path.resolve(cwd, '.abs/mcp-wrap-audit.ndjson');

  return {
    policyJson,
    shadow,
    auditPath,
    command: targetArgs[0],
    commandArgs: targetArgs.slice(1),
  };
}

export async function runStdioWrap(options: StdioWrapOptions): Promise<number> {
  const { command, commandArgs, policyJson, shadow = false } = options;
  const auditPath = options.auditPath ?? path.resolve(process.cwd(), '.abs/mcp-wrap-audit.ndjson');

  const gateway = new AbsMcpGateway({ policy: policyJson, fullPipeline: false });
  let prevHash = '0'.repeat(64);

  const child = spawn(command, commandArgs, {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: process.env,
  });

  // Pipe child stdout directly back to the MCP client on stdout
  child.stdout.on('data', (chunk: Buffer) => {
    process.stdout.write(chunk);
  });

  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  // Serialize line handling to preserve JSON-RPC ordering and hash-chain integrity
  let queue: Promise<void> = Promise.resolve();

  rl.on('line', (line: string) => {
    queue = queue.then(async () => {
      const trimmed = line.trim();
      if (!trimmed) return;

      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(trimmed) as Record<string, unknown>;
      } catch {
        // Non-JSON line — forward untouched so transport errors are handled normally
        if (!child.stdin.destroyed) child.stdin.write(line + '\n');
        return;
      }

      if (msg.method !== 'tools/call') {
        if (!child.stdin.destroyed) child.stdin.write(line + '\n');
        return;
      }

      const params = (msg.params && typeof msg.params === 'object' ? msg.params : {}) as Record<string, unknown>;
      const toolName = String(params.name ?? '');
      const toolArgs = (params.arguments && typeof params.arguments === 'object'
        ? params.arguments
        : {}) as Record<string, unknown>;

      const raw = await gateway.interceptToolCall('tools/call', {
        name: toolName,
        arguments: toolArgs,
      });

      const wouldBlock = !raw.allowed || raw.decision === 'DENY' || raw.decision === 'ESCALATE';
      const effectiveDecision = shadow
        ? wouldBlock
          ? 'SHADOW_DENY'
          : 'SHADOW_ALLOW'
        : raw.decision;
      const effectiveAllowed = shadow ? true : !wouldBlock;

      // SI-001: Seal cryptographic receipt BEFORE any execution/forwarding
      const receipt = appendHashChainedReceipt(auditPath, prevHash, {
        schema: 'abs-mcp-wrap-receipt/v1',
        recorded_at: new Date().toISOString(),
        tool: toolName,
        mode: shadow ? 'shadow' : 'enforce',
        decision: effectiveDecision,
        allowed: effectiveAllowed,
        would_block: wouldBlock,
        reason: raw.reason,
        policy_reference: raw.policyReference,
        latency_ms: raw.latencyMs,
      });
      prevHash = receipt.receipt_hash;

      if (!effectiveAllowed) {
        // SI-004: Block before reaching child MCP server and return compliant MCP tool error
        if (msg.id !== undefined) {
          const blockResponse = {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              isError: true,
              content: [
                {
                  type: 'text',
                  text: `[ABS Core ${raw.decision}] ${raw.reason} (policy: ${raw.policyReference}, receipt: sha256:${receipt.receipt_hash.slice(0, 16)})`,
                },
              ],
            },
          };
          process.stdout.write(JSON.stringify(blockResponse) + '\n');
        }
        return;
      }

      if (!child.stdin.destroyed) {
        child.stdin.write(line + '\n');
      }
    });
  });

  rl.on('close', () => {
    queue.finally(() => {
      if (!child.stdin.destroyed) child.stdin.end();
    });
  });

  const forwardSignal = (sig: NodeJS.Signals) => {
    if (!child.killed) child.kill(sig);
  };
  process.on('SIGINT', forwardSignal);
  process.on('SIGTERM', forwardSignal);

  return await new Promise<number>((resolve) => {
    child.on('error', (err) => {
      console.error(`[ABS Core wrap] Failed to start target MCP server "${command}": ${err.message}`);
      resolve(1);
    });
    child.on('close', (code) => {
      process.off('SIGINT', forwardSignal);
      process.off('SIGTERM', forwardSignal);
      resolve(code ?? 0);
    });
  });
}
