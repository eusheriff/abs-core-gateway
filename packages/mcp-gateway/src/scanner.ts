import * as fs from 'node:fs';
import * as path from 'node:path';

export interface ScanIssue {
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  description: string;
  recommendation: string;
}

export interface ScanResult {
  score: number; // 0-100
  issues: ScanIssue[];
  projectType: string;
}

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
};

export async function runSovereignScan(cwd: string): Promise<ScanResult> {
  const issues: ScanIssue[] = [];
  let score = 100;
  let projectType = 'Unknown';

  // 1. Detect AI/Agentic Project
  const pkgPath = path.join(cwd, 'package.json');
  if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    
    if (deps['@modelcontextprotocol/sdk']) projectType = 'MCP Server/Client';
    else if (deps['langchain'] || deps['openai'] || deps['anthropic']) projectType = 'AI Agent Application';

    // Check for high-risk dependencies
    if (deps['@modelcontextprotocol/server-filesystem']) {
      issues.push({
        severity: 'HIGH',
        category: 'Insecure Tooling',
        description: 'Direct FileSystem MCP access detected without interdiction layer.',
        recommendation: 'Wrap FileSystem calls with ABS Core Gateway to prevent arbitrary deletion.'
      });
      score -= 20;
    }
  }

  // 2. Check for Ungoverned Code Patterns
  const files = await getFiles(cwd, ['.ts', '.js', '.py']);
  let hasGateway = false;
  let hasToolCalls = false;

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf-8');
    if (content.includes('AbsMcpGateway')) hasGateway = true;
    if (content.includes('callTool') || content.includes('invoke')) hasToolCalls = true;

    // Check for exposed secrets (simplified regex for trial)
    if (/(sk-[a-zA-Z0-9]{32,})/.test(content)) {
      issues.push({
        severity: 'HIGH',
        category: 'Data Leakage',
        description: `Exposed API Secret found in ${path.basename(file)}.`,
        recommendation: 'Move secrets to .env and use ABS Identity Provider for encrypted key management.'
      });
      score -= 30;
    }
  }

  if (hasToolCalls && !hasGateway) {
    issues.push({
      severity: 'HIGH',
      category: 'Governance Gap',
      description: 'Active tool calls detected but no ABS Core Gateway found in code.',
      recommendation: 'Initialize AbsMcpGateway in your entry point to enable deterministic control.'
    });
    score -= 40;
  }

  // 3. Check for Identity/Audit Readiness
  const absDir = path.join(cwd, '.abs');
  if (!fs.existsSync(absDir)) {
    issues.push({
      severity: 'MEDIUM',
      category: 'Auditability',
      description: 'No ABS Core infrastructure initialized (.abs directory missing).',
      recommendation: 'Run npx @oconnectortech/mcp-gateway init to create your sovereign bunker.'
    });
    score -= 15;
  }

  // 4. Check for .env safety
  const gitignorePath = path.join(cwd, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    const gitignore = fs.readFileSync(gitignorePath, 'utf-8');
    if (fs.existsSync(path.join(cwd, '.env')) && !gitignore.includes('.env')) {
      issues.push({
        severity: 'MEDIUM',
        category: 'Compliance',
        description: '.env file found but not listed in .gitignore.',
        recommendation: 'Add .env to .gitignore immediately to prevent credential leaks.'
      });
      score -= 10;
    }
  }

  return {
    score: Math.max(0, score),
    issues,
    projectType
  };
}

async function getFiles(dir: string, extensions: string[]): Promise<string[]> {
  const results: string[] = [];
  const list = fs.readdirSync(dir);
  for (const file of list) {
    if (file === 'node_modules' || file === '.git' || file === '.abs') continue;
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat && stat.isDirectory()) {
      // recursive skip for trial speed
    } else if (extensions.includes(path.extname(file))) {
      results.push(fullPath);
    }
  }
  return results;
}

export function printScanResults(result: ScanResult): void {
  console.log(`\n${c.bold}${c.cyan}--- ABS Sovereign Scan Results ---${c.reset}`);
  console.log(`${c.bold}Project Type:${c.reset} ${result.projectType}`);
  
  const scoreColor = result.score > 80 ? c.green : result.score > 50 ? c.yellow : c.red;
  console.log(`${c.bold}Sovereign Readiness Score:${c.reset} ${scoreColor}${result.score}/100${c.reset}\n`);

  if (result.issues.length === 0) {
    console.log(`${c.green}✓ No critical vulnerabilities found.${c.reset}`);
  } else {
    for (const issue of result.issues) {
      const sevColor = issue.severity === 'HIGH' ? c.red : c.yellow;
      console.log(`${c.bold}${sevColor}[${issue.severity}]${c.reset} ${c.bold}${issue.category}:${c.reset} ${issue.description}`);
      console.log(`${c.dim}  └ Recommendation: ${issue.recommendation}${c.reset}\n`);
    }
  }

  if (result.score < 100) {
    console.log(`${c.yellow}${c.bold} PROTECT YOUR SYSTEM:${c.reset}`);
    console.log(`To fix these vulnerabilities and activate real-time interdiction,`);
    console.log(`upgrade to an ${c.bold}ABS Core Annual License${c.reset} at ${c.cyan}https://abscore.app/pricing${c.reset}\n`);
  }
}
