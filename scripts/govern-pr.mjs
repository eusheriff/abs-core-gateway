#!/usr/bin/env node
/**
 * ABS Core & CORTEX Git — Deterministic CI/PR Actuation Gatekeeper
 *
 * Evaluates pull request / commit diffs against the 5 deterministic CAIC/CORTEX-Git gates
 * BEFORE allowing code promotion or merge into protected branches:
 *   Gate 00: Revocation & Emergency Kill-Switch
 *   Gate 01: Hardcoded Secret & Credential Leak Scanner
 *   Gate 02: Destructive Execution Pattern Scanner
 *   Gate 03: Optional Ed25519 Agent Commit Attestation
 *   Gate 04: Critical Infrastructure / Migration Human Quorum Gate
 *   Gate 05: Cryptographic Sovereign Audit Record (.sar.json) & Step Summary
 *
 * Exit codes:
 *   0 = ALLOW
 *   1 = DENIED (Fail-Closed security violation)
 *   2 = QUORUM_REQUIRED (Touches critical paths without explicit M-of-N approval)
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

function getArg(args, flag, fallback = '') {
  const idx = args.indexOf(flag);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
}

const SECRET_PATTERNS = [
  { id: 'AWS_ACCESS_KEY', re: /AKIA[0-9A-Z]{16}/ },
  { id: 'GITHUB_PAT', re: /ghp_[0-9a-zA-Z]{36}/ },
  { id: 'OPENAI_KEY', re: /sk-[a-zA-Z0-9]{32,}/ },
  { id: 'PRIVATE_KEY_PEM', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { id: 'GENERIC_CREDENTIAL', re: /(?:api[_-]?key|secret|password|auth[_-]?token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/i },
];

const DANGEROUS_PATTERNS = [
  { id: 'DESTRUCTIVE_RM', re: /rm\s+-rf\s+[\/~]/ },
  { id: 'DROP_DATABASE', re: /\bdrop\s+database\b/i },
  { id: 'CURL_PIPE_SHELL', re: /(?:curl|wget)\s+[^\n|]+\|\s*(?:bash|sh|zsh)\b/ },
];

const CRITICAL_PATH_PATTERNS = [
  /(?:^|\/)migrations\//i,
  /\.sql$/i,
  /(?:^|\/)terraform\//i,
  /\.tf$/i,
  /(?:^|\/)\.github\/workflows\//i,
  /(?:^|\/)wrangler\.toml$/i,
  /(?:^|\/)Dockerfile/i,
  /(?:^|\/)policies\/.*\.rego$/i,
];

function sha256(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function collectGitDiff(baseRef, staged = false, working = false) {
  try {
    const refArgs = staged
      ? ['diff', '--cached', '--unified=0']
      : working
        ? ['diff', '--unified=0', 'HEAD']
        : baseRef
          ? ['diff', '--unified=0', `${baseRef}...HEAD`]
          : ['diff', '--unified=0', 'HEAD~1..HEAD'];
    const diff = execFileSync('git', refArgs, { encoding: 'utf8' });
    const filesArgs = staged
      ? ['diff', '--cached', '--name-only']
      : working
        ? ['diff', '--name-only', 'HEAD']
        : baseRef
          ? ['diff', '--name-only', `${baseRef}...HEAD`]
          : ['diff', '--name-only', 'HEAD~1..HEAD'];
    const files = execFileSync('git', filesArgs, { encoding: 'utf8' })
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    return { diff, files };
  } catch {
    return { diff: '', files: [] };
  }
}

function main() {
  const args = process.argv.slice(2);
  const diffFile = getArg(args, '--diff-file');
  const filesArg = getArg(args, '--files');
  const staged = args.includes('--staged');
  const working = args.includes('--working');
  const baseRef = getArg(args, '--base', process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : '');
  const outputPath = getArg(args, '--output', process.env.ABS_SAR_OUTPUT || '');
  const agentId = getArg(args, '--agent-id', process.env.ABS_AGENT_ID || 'ci-runner');
  const signatureHex = getArg(args, '--signature', process.env.ABS_AGENT_SIGNATURE || '');
  const publicKeyPem = getArg(args, '--public-key', process.env.ABS_AGENT_PUBLIC_KEY_PEM || '');
  const quorumApproved = args.includes('--quorum-approved') || process.env.ABS_QUORUM_APPROVED === 'true';
  const killSwitch = process.env.ABS_KILLSWITCH === 'true';

  let diffText = '';
  let modifiedFiles = [];
  if (diffFile) {
    diffText = fs.readFileSync(path.resolve(diffFile), 'utf8');
  } else {
    const gitData = collectGitDiff(baseRef, staged, working);
    diffText = gitData.diff;
    modifiedFiles = gitData.files;
  }
  if (filesArg) {
    modifiedFiles = filesArg.split(',').map((f) => f.trim()).filter(Boolean);
  }

  // Inspect only added lines in unified diffs to avoid false positives when deleting bad code
  const addedLines = diffText
    .split('\n')
    .filter((line) => (line.startsWith('+') && !line.startsWith('+++')) || !diffText.includes('\n@@'))
    .join('\n');

  const gates = [];
  let decision = 'ALLOW';

  // Gate 00: Kill-Switch
  const g0Passed = !killSwitch;
  if (!g0Passed) decision = 'DENIED';
  gates.push({
    gate: 'GATE_00_KILLSWITCH',
    passed: g0Passed,
    reason: g0Passed ? 'No active emergency kill-switch.' : 'FAIL_CLOSED: Emergency repository kill-switch active.',
  });

  // Gate 01: Secret Leak Scanner
  let matchedSecret = null;
  if (decision !== 'DENIED') {
    for (const rule of SECRET_PATTERNS) {
      if (rule.re.test(addedLines)) {
        matchedSecret = rule.id;
        decision = 'DENIED';
        break;
      }
    }
  }
  gates.push({
    gate: 'GATE_01_SECRET_SCANNER',
    passed: matchedSecret === null,
    reason: matchedSecret ? `FAIL_CLOSED: Hardcoded credential pattern (${matchedSecret}) detected in diff.` : 'Zero secret patterns detected.',
  });

  // Gate 02: Destructive Execution Scanner
  let matchedDanger = null;
  if (decision !== 'DENIED') {
    for (const rule of DANGEROUS_PATTERNS) {
      if (rule.re.test(addedLines)) {
        matchedDanger = rule.id;
        decision = 'DENIED';
        break;
      }
    }
  }
  gates.push({
    gate: 'GATE_02_DANGEROUS_CODE',
    passed: matchedDanger === null,
    reason: matchedDanger ? `FAIL_CLOSED: Destructive pattern (${matchedDanger}) detected in diff.` : 'Zero destructive execution patterns detected.',
  });

  // Gate 03: Optional Cryptographic Agent Attestation
  let g3Passed = true;
  let g3Reason = 'No external signature required (standard CI runner).';
  if (publicKeyPem || signatureHex) {
    try {
      const pub = crypto.createPublicKey(publicKeyPem);
      const digest = sha256(`${agentId}:${sha256(diffText)}`);
      g3Passed = crypto.verify(null, Buffer.from(digest, 'utf8'), pub, Buffer.from(signatureHex, 'hex'));
      g3Reason = g3Passed ? 'Ed25519 agent commit attestation verified.' : 'FAIL_CLOSED: Invalid Ed25519 agent signature.';
    } catch (err) {
      g3Passed = false;
      g3Reason = `FAIL_CLOSED: Attestation verification failed (${err.message}).`;
    }
    if (!g3Passed) decision = 'DENIED';
  }
  gates.push({ gate: 'GATE_03_ATTESTATION', passed: g3Passed, reason: g3Reason });

  // Gate 04: Critical Path Human Quorum
  const criticalFiles = modifiedFiles.filter((f) => CRITICAL_PATH_PATTERNS.some((re) => re.test(f)));
  let g4Passed = true;
  let g4Reason = 'No critical infrastructure, policy, or schema migration files modified.';
  if (criticalFiles.length > 0 && decision === 'ALLOW') {
    if (quorumApproved) {
      g4Reason = `Critical files (${criticalFiles.join(', ')}) authorized by explicit human quorum.`;
    } else {
      decision = 'QUORUM_REQUIRED';
      g4Passed = false;
      g4Reason = `Human M-of-N Quorum required for critical paths: ${criticalFiles.join(', ')}`;
    }
  }
  gates.push({ gate: 'GATE_04_HUMAN_QUORUM', passed: g4Passed, reason: g4Reason });

  // Gate 05: Sovereign Audit Receipt
  const diffSha256 = sha256(diffText);
  const receipt = {
    schema: 'abs-pr-governance-receipt/v1',
    sarId: `SAR-PR-${crypto.randomUUID().slice(0, 12)}`,
    evaluatedAt: new Date().toISOString(),
    agentId,
    decision,
    modifiedFiles,
    diffSha256,
    gates,
    receiptHash: '',
  };
  receipt.receiptHash = sha256(JSON.stringify({ ...receipt, receiptHash: undefined }));

  if (outputPath) {
    const absOut = path.resolve(outputPath);
    fs.mkdirSync(path.dirname(absOut), { recursive: true });
    fs.writeFileSync(absOut, JSON.stringify(receipt, null, 2) + '\n');
  }

  if (process.env.GITHUB_STEP_SUMMARY) {
    const summaryMd = [
      `### 🛡️ ABS Core PR Actuation Verdict: **${decision}**`,
      `- **SAR ID:** \`${receipt.sarId}\``,
      `- **Diff SHA-256:** \`${diffSha256}\``,
      `- **Receipt Hash:** \`${receipt.receiptHash}\``,
      '',
      '| Gate | Status | Reason |',
      '| :--- | :--- | :--- |',
      ...gates.map((g) => `| \`${g.gate}\` | ${g.passed ? '✅ PASS' : '❌ BLOCK'} | ${g.reason} |`),
      '',
    ].join('\n');
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summaryMd);
  }

  console.log(JSON.stringify(receipt, null, 2));

  if (decision === 'DENIED') process.exit(1);
  if (decision === 'QUORUM_REQUIRED') process.exit(2);
  process.exit(0);
}

main();
