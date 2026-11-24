import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { wrapTools } from './proxy';
import { renderDashboardHtml } from './dashboard-ui';
import { resolvePolicyPack } from './policy-packs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.resolve(__dirname, '../dist/cli.js');

function writeMockMcpServer(dir: string): { scriptPath: string; logPath: string } {
  const logPath = path.join(dir, 'child-received.ndjson');
  const scriptPath = path.join(dir, 'mock-mcp-server.mjs');
  writeFileSync(
    scriptPath,
    `
import * as fs from 'node:fs';
import * as readline from 'node:readline';
const logPath = ${JSON.stringify(logPath)};
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  fs.appendFileSync(logPath, JSON.stringify(msg) + '\\n');
  if (msg.id !== undefined) {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { echoed: msg.method, name: msg.params?.name ?? null } }) + '\\n');
  }
});
`,
  );
  return { scriptPath, logPath };
}

describe('MCP stdio wrap, policy packs, wrapTools & UI dashboard', () => {
  it('blocks denied tools BEFORE reaching child MCP server and forwards allowed tools with hash-chained receipts', () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'abs-wrap-enforce-'));
    try {
      const { scriptPath, logPath } = writeMockMcpServer(tempDir);
      const auditPath = path.join(tempDir, '.abs/mcp-wrap-audit.ndjson');

      const inputLines = [
        JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
        JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'fs.read', arguments: { path: 'README.md' } } }),
        JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'system.exec', arguments: { cmd: 'rm -rf /' } } }),
      ].join('\n') + '\n';

      const res = spawnSync(
        process.execPath,
        [CLI_PATH, 'wrap', '--pack', 'devsecops', '--audit', auditPath, '--', process.execPath, scriptPath],
        { cwd: tempDir, input: inputLines, encoding: 'utf8', timeout: 5000 },
      );

      expect(res.status, res.stderr).toBe(0);
      const responses = res.stdout.trim().split('\n').map((l) => JSON.parse(l));
      expect(responses).toHaveLength(3);
      const byId = new Map<number, any>(responses.map((r) => [r.id, r]));

      // 1. initialize passed through
      expect(byId.get(1)?.result.echoed).toBe('initialize');

      // 2. allowed tool passed through
      expect(byId.get(2)?.result.name).toBe('fs.read');

      // 3. denied tool blocked at proxy BEFORE child server
      expect(byId.get(3)?.result.isError).toBe(true);
      expect(byId.get(3)?.result.content[0].text).toContain('[ABS Core DENY]');

      // Child server NEVER received system.exec (SI-004)
      const childReceived = readFileSync(logPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
      expect(childReceived.map((m) => m.id)).toEqual([1, 2]);

      // Receipts hash-chained on disk (SI-001)
      const receipts = readFileSync(auditPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
      expect(receipts).toHaveLength(2);
      expect(receipts[0].decision).toBe('ALLOW');
      expect(receipts[1].decision).toBe('DENY');
      expect(receipts[1].prev_hash).toBe(receipts[0].receipt_hash);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('supports --shadow mode: logs SHADOW_DENY and still forwards to child server', () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'abs-wrap-shadow-'));
    try {
      const { scriptPath, logPath } = writeMockMcpServer(tempDir);
      const auditPath = path.join(tempDir, '.abs/shadow-audit.ndjson');
      const input = JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'system.exec', arguments: { cmd: 'whoami' } } }) + '\n';

      const res = spawnSync(
        process.execPath,
        [CLI_PATH, 'wrap', '--shadow', '--pack', 'devsecops', '--audit', auditPath, '--', process.execPath, scriptPath],
        { cwd: tempDir, input, encoding: 'utf8', timeout: 5000 },
      );

      expect(res.status, res.stderr).toBe(0);
      const childReceived = readFileSync(logPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
      expect(childReceived).toHaveLength(1);
      const receipts = readFileSync(auditPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
      expect(receipts[0].decision).toBe('SHADOW_DENY');
      expect(receipts[0].would_block).toBe(true);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('scaffolds built-in regulatory pack via `init --pack fintech-pix`', () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'abs-init-pack-'));
    try {
      const res = spawnSync(process.execPath, [CLI_PATH, 'init', '--pack', 'fintech-pix'], {
        cwd: tempDir,
        encoding: 'utf8',
        timeout: 5000,
      });
      expect(res.status, res.stderr).toBe(0);
      const policy = JSON.parse(readFileSync(path.join(tempDir, '.abs/policy.json'), 'utf8'));
      expect(policy.id).toBe('bacen-fintech-pix');
      expect(policy.escalate_tools).toContain('pix.transfer*');
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('wrapTools enforces policy in 1 line for Vercel AI SDK / plain tool maps', async () => {
    let executed = false;
    const tools = wrapTools(
      {
        'fs.read': {
          execute: async (args: { path: string }) => `read:${args.path}`,
        },
        'system.exec': async () => {
          executed = true;
          return 'boom';
        },
      },
      { pack: 'devsecops' },
    );

    await expect(tools['fs.read'].execute({ path: 'README.md' })).resolves.toBe('read:README.md');
    await expect(tools['system.exec']({ cmd: 'rm -rf /' })).rejects.toThrow('[ABS Core DENY]');
    expect(executed).toBe(false);
    expect(resolvePolicyPack('lgpd-health')?.id).toBe('lgpd-healthcare');
    expect(renderDashboardHtml('enforce')).toContain('Sovereign MCP Governance UI');
  });

  it('redteam benchmark interdicts 10/10 real-world agentic attack vectors', () => {
    const res = spawnSync(process.execPath, [CLI_PATH, 'redteam', '--json'], {
      encoding: 'utf8',
      timeout: 5000,
    });
    expect(res.status, res.stderr).toBe(0);
    const report = JSON.parse(res.stdout);
    expect(report.total).toBe(10);
    expect(report.passed).toBe(10);
    expect(report.scorecardHash).toHaveLength(64);
  });
});
