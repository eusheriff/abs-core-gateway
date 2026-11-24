/**
 * Built-in regulatory & DevSecOps policy packs bundled directly into
 * @oconnectortech/mcp-gateway so `init --pack <name>` and `wrap --pack <name>`
 * work standalone outside the monorepo.
 */

export interface PolicyPackDefinition {
  $schema: string;
  id: string;
  version: string;
  description: string;
  mode: 'enforce' | 'shadow';
  default_action: 'ALLOW' | 'DENY';
  deny_tools: string[];
  escalate_tools: string[];
  arg_restrictions: Record<string, Record<string, string>>;
}

export const BUILTIN_POLICY_PACKS: Record<string, PolicyPackDefinition> = {
  devsecops: {
    $schema: 'https://abscore.app/schemas/policy-v4.json',
    id: 'sovereign-devsecops',
    version: '6.1.0',
    description:
      'Sovereign DevSecOps Policy for Autonomous Coding Agents (Claude Code, Cursor, Codex) — Protects secrets, production infra, and destructive shell ops.',
    mode: 'enforce',
    default_action: 'ALLOW',
    deny_tools: [
      'system.exec',
      'system.shell',
      'fs.rmdir_root*',
      'git.push_force_main*',
      'cloud.destroy_cluster*',
    ],
    escalate_tools: [
      'deploy.production*',
      'k8s.apply_prod*',
      'terraform.apply*',
      'npm.publish*',
      'db.migrate_prod*',
    ],
    arg_restrictions: {
      exec_command: {
        cmd: 'deny:rm\\s+-[a-zA-Z]*r[a-zA-Z]*\\s+(/|~|\\*)|mkfs|dd\\s+if=|chmod\\s+-R\\s+777|(curl|wget).*\\|\\s*(sh|bash|zsh)',
      },
      'fs.read': {
        path: 'deny:(\\.ssh/id_|/etc/shadow|(^|/)\\.env$)',
      },
      'fs.write': {
        path: 'deny:(\\.ssh/authorized_keys|/etc/|\\.\\./)',
      },
    },
  },
  'fintech-pix': {
    $schema: 'https://abscore.app/schemas/policy-v4.json',
    id: 'bacen-fintech-pix',
    version: '6.1.0',
    description:
      'BACEN Res. 4.893 / Pix & Financial Operations Actuation Policy — Pre-execution interdiction, SQL & vault lockdown, M-of-N Quorum on transfers.',
    mode: 'enforce',
    default_action: 'ALLOW',
    deny_tools: [
      'system.exec',
      'system.shell',
      'exec_command',
      'fs.delete*',
      'db.drop*',
      'vault.export_raw_key*',
      'auth.disable_2fa*',
    ],
    escalate_tools: [
      'pix.transfer*',
      'pix.key_register*',
      'pix.key_delete*',
      'wire.transfer*',
      'ledger.reverse*',
      'credit.limit_override*',
      'db.migrate*',
    ],
    arg_restrictions: {
      'db.query': {
        sql: 'deny:DROP|TRUNCATE|ALTER\\s+TABLE|DELETE\\s+FROM\\s+(accounts|ledgers|pix_keys|audit_logs)',
      },
      'fs.read': {
        path: 'deny:\\.env|\\.pem|\\.key|id_rsa|/etc/passwd|/etc/shadow',
      },
      'fs.write': {
        path: 'deny:/etc|/sys|/proc|\\.\\./|migrations/',
      },
    },
  },
  'lgpd-health': {
    $schema: 'https://abscore.app/schemas/policy-v4.json',
    id: 'lgpd-healthcare',
    version: '6.1.0',
    description:
      'LGPD Art. 11 & Art. 18 / HIPAA Clinical Data Protection Policy — Blocks bulk PHI/PII export, enforces quorum on erasure and external sharing.',
    mode: 'enforce',
    default_action: 'ALLOW',
    deny_tools: [
      'system.exec',
      'system.shell',
      'exec_command',
      'ehr.bulk_export_unmasked*',
      'db.drop*',
      'storage.make_public*',
    ],
    escalate_tools: [
      'lgpd.cryptographic_erasure*',
      'ehr.share_external*',
      'patient.delete*',
      'consent.override*',
    ],
    arg_restrictions: {
      'db.query': {
        sql: 'deny:DROP|TRUNCATE|SELECT\\s+\\*\\s+FROM\\s+patients(?!.*LIMIT)',
      },
      'http.post': {
        body: 'deny:\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b',
      },
      'fs.read': {
        path: 'deny:\\.env|\\.pem|\\.key|dicom_raw_phi',
      },
    },
  },
};

const PACK_ALIASES: Record<string, keyof typeof BUILTIN_POLICY_PACKS> = {
  devsecops: 'devsecops',
  'sovereign-devsecops': 'devsecops',
  'fintech-pix': 'fintech-pix',
  'bacen-fintech-pix': 'fintech-pix',
  fintech: 'fintech-pix',
  'lgpd-health': 'lgpd-health',
  'lgpd-healthcare': 'lgpd-health',
  healthcare: 'lgpd-health',
};

export function resolvePolicyPack(name: string): PolicyPackDefinition | null {
  const key = PACK_ALIASES[name.trim().toLowerCase()];
  return key ? BUILTIN_POLICY_PACKS[key] : null;
}

export function listPolicyPackNames(): string[] {
  return Object.keys(BUILTIN_POLICY_PACKS);
}
