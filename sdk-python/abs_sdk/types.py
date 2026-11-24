from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional


class Action(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"


# ============================================
# VERDICT & REASON CODES
# ============================================

Verdict = Literal['ALLOW', 'DENY', 'REQUIRE_APPROVAL']

ReasonCode = Literal[
    'POLICY.VIOLATION',
    'RISK.EXCEEDED',
    'BUDGET.EXHAUSTED',
    'RATE.LIMITED',
    'OPS.MAINTENANCE'
]


# ============================================
# POLICY
# ============================================

@dataclass
class Policy:
    name: str
    action: Literal['ALLOW', 'DENY', 'SANITIZE', 'REQUIRE_APPROVAL']
    description: Optional[str] = None
    pattern: Optional[str] = None
    risk: Optional[float] = None
    remediation: Optional[str] = None


# ============================================
# SIGNATURES & IDENTITIES
# ============================================

@dataclass
class Signature:
    alg: Literal['HMAC-SHA256', 'EdDSA', 'RS256']
    key_id: str
    value: str


# ============================================
# DECISION ENVELOPE (ADR-008 v1.0.0)
# ============================================

@dataclass
class Authority:
    policy_name: str
    policy_version: str
    evaluated_at: str


@dataclass
class Applicability:
    required_checks: List[str]
    jurisdiction: Optional[str] = None
    monitor_mode: Optional[bool] = None


@dataclass
class DecisionContext:
    tenant_id: str
    agent_id: str
    event_type: str
    action_requested: str
    session_id: Optional[str] = None


@dataclass
class DecisionEnvelope:
    contract_version: Literal['1.0.0']
    decision_id: str
    trace_id: str
    timestamp: str
    signature: Signature
    decision_type: Literal['GOVERNANCE', 'OPERATIONAL']
    verdict: Verdict
    reason_code: ReasonCode
    reason_human: str
    risk_score: float
    authority: Authority
    context: DecisionContext
    valid_until: Optional[str] = None
    applicability: Optional[Applicability] = None
    remediation: Optional[str] = None


# ============================================
# EXECUTION RECEIPT (ADR-008)
# ============================================

@dataclass
class GateResult:
    result: Literal['PASS', 'FAIL', 'SKIPPED']
    checked_at: str
    source: str
    skip_reason: Optional[str] = None
    skip_policy_version: Optional[str] = None


@dataclass
class Evidence:
    input_hash: Optional[str] = None
    output_hash: Optional[str] = None
    external_refs: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ExecutionContext:
    environment: str
    tenant_id: str
    # other contextual key/values
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionReceipt:
    receipt_id: str
    decision_id: str
    execution_id: str
    timestamp: str
    executor_id: str
    execution_context: ExecutionContext
    gates: Dict[str, GateResult]
    outcome: Literal['EXECUTED', 'BLOCKED', 'SKIPPED']
    details: Optional[str] = None
    evidence: Optional[Evidence] = None
    signature: Optional[Signature] = None
