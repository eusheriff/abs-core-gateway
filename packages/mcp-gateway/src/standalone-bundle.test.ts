import { describe, it, expect } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_DIR = path.resolve(__dirname, '..');

describe('@oconnectortech/mcp-gateway standalone npm bundle', () => {
  it('packs into a self-contained tarball with zero workspace:* runtime dependencies and executes outside the monorepo', () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'abs-mcp-pack-'));
    try {
      const packOut = execFileSync('corepack', ['pnpm', 'pack', '--pack-destination', tempDir], {
        cwd: PKG_DIR,
        encoding: 'utf8',
      }).trim();
      const tarballName = packOut.split('\n').pop()!.trim();
      const tarballPath = path.isAbsolute(tarballName) ? tarballName : path.join(tempDir, path.basename(tarballName));

      execFileSync('tar', ['-xzf', tarballPath, '-C', tempDir]);
      const packedPkgJson = JSON.parse(readFileSync(path.join(tempDir, 'package/package.json'), 'utf8'));

      const runtimeDeps = {
        ...(packedPkgJson.dependencies ?? {}),
        ...(packedPkgJson.optionalDependencies ?? {}),
        ...(packedPkgJson.peerDependencies ?? {}),
      };
      for (const [depName, spec] of Object.entries(runtimeDeps)) {
        expect(String(spec), `Dependency ${depName} leaked workspace protocol: ${spec}`).not.toContain('workspace:');
        expect(depName.startsWith('@abs-core/'), `Private internal package ${depName} leaked into runtime dependencies`).toBe(false);
      }

      // Execute standalone local policy evaluation directly from the extracted tarball outside the monorepo
      const evalScript = `
        import { AbsMcpGateway } from './package/dist/proxy.js';
        const gw = new AbsMcpGateway({
          policy: JSON.stringify({ id: 'standalone-test', deny_tools: ['system.exec'] }),
          fullPipeline: false,
        });
        const deny = await gw.interceptToolCall('tools/call', { name: 'system.exec', arguments: { cmd: 'rm -rf /' } });
        const allow = await gw.interceptToolCall('tools/call', { name: 'fs.read', arguments: { path: 'README.md' } });
        if (deny.decision !== 'DENY' || !allow.allowed) process.exit(1);
      `;
      const runRes = spawnSync(process.execPath, ['--input-type=module', '-e', evalScript], {
        cwd: tempDir,
        encoding: 'utf8',
      });
      expect(runRes.status, runRes.stderr || runRes.stdout).toBe(0);

      const helpRes = spawnSync(process.execPath, [path.join(tempDir, 'package/dist/cli.js'), '--help'], {
        cwd: tempDir,
        encoding: 'utf8',
        timeout: 3000,
      });
      expect(helpRes.status, helpRes.stderr || helpRes.stdout).toBe(0);
      expect(helpRes.stdout).toContain('serve');
      expect(helpRes.stdout).not.toContain('Real-time watch mode starting');
      expect(helpRes.stderr).not.toContain('@abs-core/threat-intel');
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
