/**
 * ABS Core MCP Gateway — Security Proxy for Model Context Protocol
 *
 * Intercepts ALL MCP tool calls and routes them through the NRaaS pipeline
 * before forwarding to the actual MCP Server. This makes governance an
 * inevitable consequence of using the protocol.
 *
 * Architecture:
 *   MCP Client (Agent) → ABS MCP Gateway → NRaaS Pipeline → MCP Server (Tool)
 *
 * The gateway acts as both an MCP Server (from the client's perspective)
 * and an MCP Client (connecting to the real upstream server).
 *
 * @module @oconnector/mcp-gateway/proxy
 * @version 4.3.3
 */

import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

// Lazy-loaded full NRaaS pipeline modules so standalone npm consumers (`fullPipeline: false`)
// run with zero monorepo/native addon requirements while full-pipeline deployments preserve 11-gate enforcement.
let _pipelineModulesPromise: Promise<{ GatewayPipeline: any; LlmEngineValidator: any }> | null = null;
async function loadFullPipelineModules() {
  if (!_pipelineModulesPromise) {
    const gpMod = '@abs-core/quorum/dist/gateway/gateway-pipeline.js';
    const llmMod = '@abs-core/quorum/dist/gateway/state-02-llm.js';
    _pipelineModulesPromise = Promise.all([
      import(gpMod),
      import(llmMod),
    ]).then(([gp, llm]) => ({
      GatewayPipeline: gp.GatewayPipeline,
      LlmEngineValidator: llm.LlmEngineValidator,
    })).catch((err) => {
      _pipelineModulesPromise = null;
      throw err;
    });
  }
  return _pipelineModulesPromise;
}

const registeredMcpTools = new Set<string>();
const MAX_REGISTERED_MCP_TOOLS = 1024;

// ── Types ──

export interface MCPToolCall {
  /** MCP method (e.g., 'tools/call') */
  method: string;
  /** Tool name being invoked */
  toolName: string;
  /** Tool arguments */
  args: Record<string, any>;
  /** MCP request ID for correlation */
  requestId: string | number;
}

export interface GatewayDecision {
  /** Whether the tool call was allowed */
  allowed: boolean;
  /** Governance decision */
  decision: 'ALLOW' | 'DENY' | 'ESCALATE';
  /** Reason for the decision */
  reason: string;
  /** Policy that produced this decision */
  policyReference: string;
  /** NRaaS pipeline latency in ms */
  latencyMs: number;
  /** Crypto receipt for non-repudiation */
  cryptoReceipt: string;
  /** RFC 3161 temporal proof */
  rfc3161Authority: string;
  /** Hash of the tool call for verification */
  toolCallHash: string;
  /** ISO timestamp */
  timestamp: string;
}

export interface GatewayConfig {
  /** Policy JSON or path to policy file */
  policy?: string;
  /** Whether to log all decisions to console */
  verbose?: boolean;
  /**
   * Maximum pipeline latency threshold (ms) for monitoring/alerting only.
   * Exceeding this threshold does NOT auto-allow the request (SI-004: Fail-Closed).
   * The pipeline always returns DENY on timeout — never ALLOW.
   */
  maxLatencyMs?: number;
  /** Agent ID for OID tracking */
  agentId?: string;
  /** Ed25519 signature for OID verification */
  oidSignature?: string;
  /** Universal Trace ID for cross-component correlation */
  traceId?: string;
  /**
   * Routes ALLOW decisions through the full 11-gate NRaaS pipeline
   * (OID, TOOL_VALIDATE, WASM engine, ledger seal). Enabled by default. Set
   * false only for an explicitly selected non-production local policy mode.
   */
  fullPipeline?: boolean;
}

/** Convert the human-facing MCP policy map into the WASM engine's rule array. */
function toPipelinePolicy(policy?: string): string | undefined {
  if (!policy) return undefined;
  try {
    const parsed = JSON.parse(policy) as any;
    if (Array.isArray(parsed)) return policy;
    const rules: Array<Record<string, unknown>> = [];
    for (const [index, pattern] of (parsed.deny_tools ?? []).entries()) {
      if (typeof pattern === 'string') rules.push({ id: `mcp-deny-${index}`, agent_pattern: '*', action_pattern: pattern, decision: 'DENY', priority: 10 });
    }
    // The local evaluator remains authoritative for argument restrictions and
    // escalations; this rule supplies the WASM engine's explicit default allow.
    rules.push({ id: 'mcp-default-allow', agent_pattern: '*', action_pattern: '*', decision: 'ALLOW', priority: 100 });
    return JSON.stringify(rules);
  } catch {
    return undefined;
  }
}

export type GatewayEvent =
  | { type: 'INTERCEPTED'; toolCall: MCPToolCall; timestamp: string }
  | { type: 'DECIDED'; toolCall: MCPToolCall; decision: GatewayDecision }
  | { type: 'FORWARDED'; toolCall: MCPToolCall; timestamp: string }
  | { type: 'BLOCKED'; toolCall: MCPToolCall; decision: GatewayDecision }
  | { type: 'ERROR'; toolCall: MCPToolCall; error: string };

// ── Gateway Engine ──

export class AbsMcpGateway extends EventEmitter {
  private config: GatewayConfig;
  private stats = {
    totalIntercepted: 0,
    totalAllowed: 0,
    totalBlocked: 0,
    totalEscalated: 0,
    totalErrors: 0,
    avgLatencyMs: 0,
  };

  constructor(config: GatewayConfig = {}) {
    super();
    if (config.fullPipeline === false && process.env.NODE_ENV === 'production') {
      throw new Error('ABS MCP Gateway cannot disable the governance pipeline in production.');
    }
    this.config = {
      verbose: true,
      maxLatencyMs: 50,
      agentId: 'mcp-agent',
      fullPipeline: true,
      ...config,
    };
  }

  /**
   * Intercepts an MCP tool_call request and evaluates it against policies.
   *
   * This is the core method — sits between the MCP Client and MCP Server.
   * Returns a GatewayDecision that determines whether the tool call proceeds.
   *
   * @param method - MCP method (e.g., 'tools/call')
   * @param params - MCP request parameters containing tool name and arguments
   * @returns GatewayDecision with allow/deny result and crypto receipt
   */
  async interceptToolCall(
    method: string,
    params: Record<string, any>
  ): Promise<GatewayDecision> {
    const start = performance.now();
    const toolName = params.name || params.tool || 'unknown';
    const args = params.arguments || params.args || {};
    const requestId = params._meta?.requestId || crypto.randomUUID();
    const traceId = params._meta?.traceId || this.config.traceId || crypto.randomUUID();

    const toolCall: MCPToolCall = {
      method,
      toolName,
      args,
      requestId,
    };

    this.stats.totalIntercepted++;

    // Emit interception event (for CLI watch)
    this.emit('event', {
      type: 'INTERCEPTED',
      toolCall,
      timestamp: new Date().toISOString(),
    } satisfies GatewayEvent);

    try {
      // --- Camada 1: policy MCP local (deny_tools / escalate_tools / arg_restrictions) ---
      // O schema de policy MCP e avaliado aqui; o engine WASM do pipeline usa outro
      // schema (array de regras) e nao entende este formato.
      const toolCallHash = crypto
        .createHash('sha256')
        .update(JSON.stringify({ method, toolName, args }))
        .digest('hex');

      const localDecision = this.evaluatePolicy(toolCall, toolCallHash);
      if (!localDecision.allowed) {
        const localLatency = performance.now() - start;
        const decision: GatewayDecision = {
          ...localDecision,
          latencyMs: Math.round(localLatency * 100) / 100,
          toolCallHash,
          timestamp: new Date().toISOString(),
        };
        if (decision.decision === 'ESCALATE') {
          this.stats.totalEscalated++;
        } else {
          this.stats.totalBlocked++;
        }
        this.updateAvgLatency(localLatency);
        this.emit('event', { type: 'BLOCKED', toolCall, decision } satisfies GatewayEvent);
        return decision;
      }

      // Caminho rapido (default): decisao local ALLOW e final — mantem P50 < 1ms.
      if (!this.config.fullPipeline) {
        const localLatency = performance.now() - start;
        const decision: GatewayDecision = {
          ...localDecision,
          latencyMs: Math.round(localLatency * 100) / 100,
          toolCallHash,
          timestamp: new Date().toISOString(),
        };
        this.stats.totalAllowed++;
        this.updateAvgLatency(localLatency);
        this.emit('event', { type: 'DECIDED', toolCall, decision } satisfies GatewayEvent);
        return decision;
      }

      // --- Camada 2 (fullPipeline): v4.3.3 NRaaS Unified Pipeline ---
      // We map the MCP tool call into the unified ABS Core intent payload
      const intentPayload = createMcpGovernanceIntent(
        this.config.agentId || 'anonymous',
        toolName,
        args,
        traceId,
      );
      const oidSignature = params._meta?.oidSignature ??
        params._meta?.oid_signature ?? this.config.oidSignature;
      Object.assign(intentPayload, {
        oid_signature: oidSignature,
      });

      const { GatewayPipeline, LlmEngineValidator } = await loadFullPipelineModules();

      // MCP servers are extensible by design. Register an unknown MCP tool once
      // (bounded) so STATE_02 can validate it deterministically without mutating
      // or leaking memory on every request.
      if (!registeredMcpTools.has(toolName) && registeredMcpTools.size < MAX_REGISTERED_MCP_TOOLS) {
        registeredMcpTools.add(toolName);
        LlmEngineValidator.registerTool({
          name: toolName,
          riskWeight: 7,
          maxTimeoutMs: 30_000,
          category: 'network',
        });
      }

      // Execute the full 11-stage pipeline (policy MCP ja avaliada na camada 1)
      const pipelineResult = await GatewayPipeline.execute(
        intentPayload,
        { role: 'agent', status: 'active', id: this.config.agentId || 'anonymous' }, // Identity payload
        null, // No prevHop for direct gateway calls
        toPipelinePolicy(this.config.policy) // Keep the deterministic WASM engine aligned with the MCP policy.
      );

      const latencyMs = performance.now() - start;

      const gatewayDecision: GatewayDecision = {
        allowed: pipelineResult.success,
        decision: pipelineResult.success ? 'ALLOW' : (pipelineResult.stage === 'QUORUM' ? 'ESCALATE' : 'DENY'),
        reason: pipelineResult.success ? 'Allowed by ABS Core NRaaS Pipeline' : (pipelineResult.error || 'Blocked by governance policy'),
        policyReference: (pipelineResult.auditRecord as any)?.policy_ref || 'abs-core-pipeline',
        latencyMs: Math.round(latencyMs * 100) / 100,
        cryptoReceipt: pipelineResult.auditRecord?.crypto_receipt || `sha256:${toolCallHash}`,
        rfc3161Authority: (pipelineResult.auditRecord as any)?.rfc3161_authority || (pipelineResult.auditRecord as any)?.tsa_proof || '',
        toolCallHash: (pipelineResult.auditRecord as any)?.intent_hash || toolCallHash,
        timestamp: new Date().toISOString(),
      };

      // Update stats
      if (gatewayDecision.allowed) {
        this.stats.totalAllowed++;
      } else if (gatewayDecision.decision === 'ESCALATE') {
        this.stats.totalEscalated++;
      } else {
        this.stats.totalBlocked++;
      }
      this.updateAvgLatency(latencyMs);

      // Emit decision event
      const eventType = gatewayDecision.allowed ? 'FORWARDED' : 'BLOCKED';
      this.emit('event', {
        type: eventType === 'FORWARDED' ? 'DECIDED' : 'BLOCKED',
        toolCall,
        decision: gatewayDecision,
      } satisfies GatewayEvent);

      return gatewayDecision;

    } catch (error: any) {
      // OID enforcement errors (unsigned/anonymous agents) = DENY, not error
      // Only true gateway failures count as errors
      const isOidFailure = error.message?.includes('OID') || 
                           error.message?.includes('unsigned') ||
                           error.message?.includes('signature') ||
                           error.message?.includes('anonymous') ||
                           error.message?.includes('Inception');

      if (isOidFailure) {
        this.stats.totalBlocked++;
      } else {
        this.stats.totalErrors++;
      }
      const latencyMs = performance.now() - start;

      this.emit('event', {
        type: 'ERROR',
        toolCall,
        error: error.message,
      } satisfies GatewayEvent);

      // Fail-closed: deny on error
      return {
        allowed: false,
        decision: 'DENY',
        reason: `FAIL_CLOSED: Gateway error — ${error.message}`,
        policyReference: 'gateway-error-handler',
        latencyMs: Math.round(latencyMs * 100) / 100,
        cryptoReceipt: '',
        rfc3161Authority: '',
        toolCallHash: '',
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Evaluates a tool call against the configured policy.
   */
  private evaluatePolicy(
    toolCall: MCPToolCall,
    toolCallHash: string
  ): Omit<GatewayDecision, 'latencyMs' | 'toolCallHash' | 'timestamp'> {
    // Parse policy if provided
    let policy: any = { default_action: 'ALLOW' };
    if (this.config.policy) {
      try {
        policy = JSON.parse(this.config.policy);
      } catch {
        // Policy parse error — fail closed
        return {
          allowed: false,
          decision: 'DENY',
          reason: 'FAIL_CLOSED: Invalid policy JSON',
          policyReference: 'policy-parse-error',
          cryptoReceipt: `sha256:${toolCallHash}`,
          rfc3161Authority: '',
        };
      }
    }

    // --- HASHED KEY VALIDATION (Elite v4.3.3) ---
    // If an API key is provided, validate it against hashed entries
    // For demo/standalone purposes, we assume keys are in policy.keys
    if (this.config.agentId && policy.keys) {
        const providedKey = this.config.agentId; // For MCP, we often use IDs as identifiers
        const keyHash = crypto.createHash('sha256').update(providedKey).digest('hex');
        const allowedHashes = policy.keys.map((k: string) => k.startsWith('sha256:') ? k.split(':')[1] : null).filter(Boolean);
        
        if (allowedHashes.length > 0 && !allowedHashes.includes(keyHash)) {
            return {
                allowed: false,
                decision: 'DENY',
                reason: 'Authentication failed: Invalid or unauthorized Agent ID hash.',
                policyReference: 'agent-auth-fail',
                cryptoReceipt: `sha256:${toolCallHash}`,
                rfc3161Authority: '',
            };
        }
    }

    // Check deny_tools list
    if (policy.deny_tools && Array.isArray(policy.deny_tools)) {
      for (const pattern of policy.deny_tools) {
        if (this.matchToolPattern(toolCall.toolName, pattern)) {
          return {
            allowed: false,
            decision: 'DENY',
            reason: `Tool "${toolCall.toolName}" is blocked by policy (pattern: ${pattern})`,
            policyReference: policy.id || 'deny-list',
            cryptoReceipt: `sha256:${toolCallHash}`,
            rfc3161Authority: '',
          };
        }
      }
    }

    // Check escalate_tools list
    if (policy.escalate_tools && Array.isArray(policy.escalate_tools)) {
      for (const pattern of policy.escalate_tools) {
        if (this.matchToolPattern(toolCall.toolName, pattern)) {
          return {
            allowed: false,
            decision: 'ESCALATE',
            reason: `Tool "${toolCall.toolName}" requires human approval (pattern: ${pattern})`,
            policyReference: policy.id || 'escalate-list',
            cryptoReceipt: `sha256:${toolCallHash}`,
            rfc3161Authority: '',
          };
        }
      }
    }

    // Check argument restrictions
    if (policy.arg_restrictions && policy.arg_restrictions[toolCall.toolName]) {
      const restrictions = policy.arg_restrictions[toolCall.toolName];
      for (const [argName, rule] of Object.entries(restrictions)) {
        const argValue = toolCall.args[argName];
        if (typeof rule === 'string' && rule.startsWith('deny:')) {
          const denyPattern = rule.slice(5);
          if (String(argValue).match(new RegExp(denyPattern))) {
            return {
              allowed: false,
              decision: 'DENY',
              reason: `Argument "${argName}" value blocked by policy restriction`,
              policyReference: policy.id || 'arg-restriction',
              cryptoReceipt: `sha256:${toolCallHash}`,
              rfc3161Authority: '',
            };
          }
        }
      }
    }

    if (String(policy.default_action).toUpperCase() === 'DENY') {
      return {
        allowed: false,
        decision: 'DENY',
        reason: `Tool "${toolCall.toolName}" denied by default_action: DENY policy`,
        policyReference: policy.id || 'default-deny',
        cryptoReceipt: `sha256:${toolCallHash}`,
        rfc3161Authority: '',
      };
    }

    // Default: allow
    return {
      allowed: true,
      decision: 'ALLOW',
      reason: 'Allowed by MCP Gateway policy evaluation',
      policyReference: policy.id || 'default',
      cryptoReceipt: `sha256:${toolCallHash}`,
      rfc3161Authority: '',
    };
  }

  /**
   * Matches a tool name against a glob-style pattern.
   * Supports: exact match, prefix wildcard (db.*), suffix (*_delete)
   */
  private matchToolPattern(toolName: string, pattern: string): boolean {
    if (pattern === '*') return true;
    if (pattern === toolName) return true;

    // Glob: db.* matches db.query, db.insert, etc.
    if (pattern.endsWith('*')) {
      return toolName.startsWith(pattern.slice(0, -1));
    }
    if (pattern.startsWith('*')) {
      return toolName.endsWith(pattern.slice(1));
    }

    // Regex pattern
    if (pattern.startsWith('regex:')) {
      return new RegExp(pattern.slice(6)).test(toolName);
    }

    return false;
  }

  /**
   * Updates the running average latency.
   */
  private updateAvgLatency(latencyMs: number): void {
    const total = this.stats.totalIntercepted;
    this.stats.avgLatencyMs =
      ((this.stats.avgLatencyMs * (total - 1)) + latencyMs) / total;
  }

  /**
   * Returns current gateway statistics.
   */
  getStats(): typeof this.stats {
    return { ...this.stats };
  }

  /**
   * Creates a JSON-RPC error response for blocked tool calls.
   * Compatible with MCP protocol error format.
   */
  static createBlockResponse(
    requestId: string | number,
    decision: GatewayDecision
  ): object {
    return {
      jsonrpc: '2.0',
      id: requestId,
      error: {
        code: decision.decision === 'ESCALATE' ? -32001 : -32003,
        message: `[ABS_GATEWAY] ${decision.decision}: ${decision.reason}`,
        data: {
          decision: decision.decision,
          policyReference: decision.policyReference,
          cryptoReceipt: decision.cryptoReceipt,
          toolCallHash: decision.toolCallHash,
          latencyMs: decision.latencyMs,
        },
      },
    };
  }
}

/** Shared payload shape for agent-side Ed25519 signing and gateway verification. */
export function createMcpGovernanceIntent(
  agentId: string,
  toolName: string,
  args: Record<string, unknown>,
  traceId: string,
): Record<string, unknown> {
  return {
    agent_id: agentId,
    action: toolName,
    context: args,
    tools: [toolName],
    tool_params: { [toolName]: args },
    trace_id: traceId,
  };
}

import { BUILTIN_POLICY_PACKS, resolvePolicyPack, listPolicyPackNames } from './policy-packs';
export { BUILTIN_POLICY_PACKS, resolvePolicyPack, listPolicyPackNames };

export interface GovernedToolLike {
  execute?: (...args: any[]) => Promise<any> | any;
  [key: string]: any;
}

/**
 * 1-line governance wrapper for Vercel AI SDK tool maps or plain async tool functions.
 *
 * Example:
 *   const tools = wrapTools({ readFile, execShell }, { pack: 'devsecops' });
 */
export function wrapTools<T extends Record<string, GovernedToolLike | ((...args: any[]) => any)>>(
  tools: T,
  gatewayOrOptions: AbsMcpGateway | { policy?: string; pack?: string; shadow?: boolean } = {},
): T {
  const isShadow = !(gatewayOrOptions instanceof AbsMcpGateway) && Boolean(gatewayOrOptions.shadow);
  let gateway: AbsMcpGateway;
  if (gatewayOrOptions instanceof AbsMcpGateway) {
    gateway = gatewayOrOptions;
  } else {
    let policy = gatewayOrOptions.policy;
    if (!policy && gatewayOrOptions.pack) {
      const pack = resolvePolicyPack(gatewayOrOptions.pack);
      if (!pack) {
        throw new Error(`Unknown ABS policy pack: ${gatewayOrOptions.pack}`);
      }
      policy = JSON.stringify(pack);
    }
    gateway = new AbsMcpGateway({ policy, fullPipeline: false });
  }

  const guarded: Record<string, unknown> = {};
  for (const [toolName, toolDef] of Object.entries(tools)) {
    const enforce = async (rawArgs: unknown) => {
      const argObj = rawArgs && typeof rawArgs === 'object' ? (rawArgs as Record<string, unknown>) : { input: rawArgs };
      const decision = await gateway.interceptToolCall('tools/call', { name: toolName, arguments: argObj });
      if (!isShadow && (!decision.allowed || decision.decision !== 'ALLOW')) {
        const err = new Error(`[ABS Core ${decision.decision}] ${decision.reason} (receipt: ${decision.cryptoReceipt})`);
        (err as any).absDecision = decision;
        throw err;
      }
    };

    if (typeof toolDef === 'function') {
      guarded[toolName] = async (...callArgs: any[]) => {
        await enforce(callArgs[0]);
        return await toolDef(...callArgs);
      };
    } else if (toolDef && typeof toolDef.execute === 'function') {
      const origExecute = toolDef.execute.bind(toolDef);
      guarded[toolName] = {
        ...toolDef,
        execute: async (...callArgs: any[]) => {
          await enforce(callArgs[0]);
          return await origExecute(...callArgs);
        },
      };
    } else {
      guarded[toolName] = toolDef;
    }
  }

  return guarded as T;
}
