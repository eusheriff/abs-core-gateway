"""
ABS Core Python SDK
-------------------

Official Python SDK for ABS Core — AI Agent Governance Infrastructure.

Usage:
    from abs_sdk import ABSClient, parseDSN

    client = ABSClient(dsn="abs://my-workspace.abscore.app", token="abs_pat_xxx")

    # Evaluate a tool call before executing
    verdict = client.evaluate_tool("fs.write", {"path": "/etc/passwd", "content": "..."})
    if verdict.decision == "DENY":
        raise PermissionError(f"Blocked by ABS: {verdict.reason}")

    # Send heartbeat
    client.heartbeat("agent-123")

    # Check bond status
    bond = client.get_bond("agent-123")
"""

from __future__ import annotations

import json
import time
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError


# ==========================================
# DSN Parser
# ==========================================

DSN_PATTERN = re.compile(r"^abs://([a-zA-Z0-9_-]+)(?:\.([a-zA-Z0-9.-]+))?$")


@dataclass
class ParsedDSN:
    protocol: str
    workspace_id: str
    host: str
    base_url: str
    ws_url: str


def parse_dsn(dsn: str) -> ParsedDSN:
    """Parse an ABS DSN string into components.

    Args:
        dsn: DSN string (e.g., "abs://my-workspace.abscore.app")

    Returns:
        ParsedDSN with base_url and ws_url computed

    Raises:
        ValueError: If DSN format is invalid
    """
    if not dsn:
        raise ValueError("DSN is required")

    match = DSN_PATTERN.match(dsn.strip())
    if not match:
        raise ValueError(f"Invalid DSN format: {dsn}. Expected: abs://<workspace>.abscore.app")

    workspace_id = match.group(1)
    host = match.group(2) or "abscore.app"

    return ParsedDSN(
        protocol="abs",
        workspace_id=workspace_id,
        host=host,
        base_url=f"https://{workspace_id}.{host}/v1",
        ws_url=f"wss://{workspace_id}.{host}/v1/ws",
    )


# ==========================================
# Data Classes
# ==========================================


@dataclass
class PolicyResult:
    status: str  # ALLOWED | DENIED
    reason: Optional[str] = None
    risk_score: float = 0.0
    policy_matched: Optional[str] = None


@dataclass
class MCPVerdict:
    tool_call_id: str
    tool_name: str
    decision: str  # ALLOW | DENY | FLAG
    policy_result: PolicyResult
    entropy_score: float = 0.0
    entropy_flags: list[str] = field(default_factory=list)
    bond_slashed: bool = False
    slash_amount: Optional[float] = None
    timestamp: str = ""
    trace_id: str = ""


@dataclass
class Bond:
    id: str
    agent_id: str
    amount: float
    balance: float
    currency: str
    status: str
    created_at: str
    updated_at: str


@dataclass
class EntropyResult:
    bits_per_char: float
    payload_length: int
    unique_chars: int
    max_entropy: float
    is_high_entropy: bool
    normalized_ratio: float
    detected_patterns: list[str] = field(default_factory=list)


# ==========================================
# Client
# ==========================================


class ABSClient:
    """ABS Core Python SDK Client.

    Args:
        dsn: ABS DSN string (e.g., "abs://workspace.abscore.app")
            or base_url directly (e.g., "https://api.abscore.app/v1")
        token: ABS API token (Bearer token)
        timeout: Request timeout in seconds (default: 10)
    """

    def __init__(
        self,
        dsn: Optional[str] = None,
        base_url: Optional[str] = None,
        token: str = "",
        timeout: int = 10,
    ):
        if dsn:
            parsed = parse_dsn(dsn)
            self._base_url = parsed.base_url
        elif base_url:
            self._base_url = base_url.rstrip("/")
        else:
            raise ValueError("Either dsn or base_url is required")

        self._token = token
        self._timeout = timeout

    def _request(
        self, method: str, path: str, body: Optional[dict] = None
    ) -> dict[str, Any]:
        """Make an HTTP request to the ABS API."""
        url = f"{self._base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._token}",
        }

        data = json.dumps(body).encode() if body else None
        req = Request(url, data=data, headers=headers, method=method)

        try:
            with urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode())
        except HTTPError as e:
            error_body = e.read().decode() if e.fp else ""
            raise RuntimeError(f"ABS API Error: {e.code} {e.reason} — {error_body}") from e

    # ------------------------------------------
    # Health
    # ------------------------------------------

    def health(self) -> dict:
        """Check ABS Core health status."""
        return self._request("GET", "/../health")

    # ------------------------------------------
    # MCP Bridge
    # ------------------------------------------

    @staticmethod
    def _parse_verdict_payload(raw: dict[str, Any], fallback_tool_name: str = "") -> MCPVerdict:
        """Parse either Sentinel Cloud (/mcp/tool-call) or Universal Gateway (/authorize) payload fail-closed (SI-004)."""
        # Universal Gateway shape: {"trace_id": "...", "tool": "...", "decision": {"allowed": bool, "decision": "ALLOW|DENY|ESCALATE", ...}}
        if isinstance(raw.get("decision"), dict):
            gw_dec = raw["decision"]
            raw_decision = str(gw_dec.get("decision", "DENY")).upper()
            if raw_decision not in ("ALLOW", "DENY", "FLAG", "ESCALATE"):
                raw_decision = "DENY"
            if raw_decision == "ALLOW" and gw_dec.get("allowed") is not True:
                raw_decision = "DENY"
            status = "ALLOWED" if raw_decision == "ALLOW" else "DENIED"
            return MCPVerdict(
                tool_call_id=str(raw.get("toolCallId", raw.get("trace_id", ""))),
                tool_name=str(raw.get("tool", fallback_tool_name)),
                decision=raw_decision,
                policy_result=PolicyResult(
                    status=status,
                    reason=gw_dec.get("reason") or ("Allowed" if status == "ALLOWED" else "Denied by ABS Core"),
                    risk_score=float(gw_dec.get("riskScore", 0.0)),
                    policy_matched=gw_dec.get("policyReference"),
                ),
                timestamp=str(gw_dec.get("timestamp", raw.get("recorded_at", ""))),
                trace_id=str(raw.get("trace_id", "")),
            )

        v = raw.get("verdict", raw)
        if not isinstance(v, dict) or not isinstance(v.get("decision"), str):
            return MCPVerdict(
                tool_call_id="",
                tool_name=fallback_tool_name,
                decision="DENY",
                policy_result=PolicyResult(
                    status="DENIED",
                    reason="Fail-closed: missing or invalid governance decision (SI-004)",
                ),
            )

        raw_decision = v["decision"].upper()
        if raw_decision not in ("ALLOW", "DENY", "FLAG", "ESCALATE"):
            raw_decision = "DENY"

        pr = v.get("policyResult") if isinstance(v.get("policyResult"), dict) else {}
        default_status = "ALLOWED" if raw_decision == "ALLOW" else "DENIED"
        return MCPVerdict(
            tool_call_id=v.get("toolCallId", ""),
            tool_name=v.get("toolName", fallback_tool_name),
            decision=raw_decision,
            policy_result=PolicyResult(
                status=pr.get("status", default_status),
                reason=pr.get("reason"),
                risk_score=pr.get("risk_score", 0),
                policy_matched=pr.get("policy_matched"),
            ),
            entropy_score=v.get("entropyScore", 0),
            entropy_flags=v.get("entropyFlags", []),
            bond_slashed=v.get("bondSlashed", False),
            slash_amount=v.get("slashAmount"),
            timestamp=v.get("timestamp", ""),
            trace_id=v.get("traceId", ""),
        )

    def evaluate_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> MCPVerdict:
        """Evaluate a tool call against the ABS Policy Engine.

        Args:
            tool_name: MCP tool name (e.g., "fs.write", "shell.exec")
            arguments: Tool call arguments
            agent_id: Optional agent identity
            trace_id: Optional trace ID for correlation

        Returns:
            MCPVerdict with decision (ALLOW/DENY/FLAG)
        """
        body = {
            "name": tool_name,
            "arguments": arguments,
            "agentId": agent_id,
            "traceId": trace_id,
        }
        resp = self._request("POST", "/mcp/tool-call", body)
        return self._parse_verdict_payload(resp, fallback_tool_name=tool_name)

    def evaluate_batch(
        self,
        tool_calls: list[dict[str, Any]],
    ) -> list[MCPVerdict]:
        """Evaluate multiple tool calls in batch.

        Args:
            tool_calls: List of {"name": str, "arguments": dict} objects

        Returns:
            List of MCPVerdict objects
        """
        body = {"toolCalls": tool_calls}
        resp = self._request("POST", "/mcp/batch", body)
        verdicts = resp.get("verdicts", [])
        return [self._parse_verdict_payload(v) for v in verdicts]

    def mcp_capabilities(self) -> dict:
        """Get MCP governance capabilities."""
        return self._request("GET", "/mcp/capabilities")

    # ------------------------------------------
    # Agents
    # ------------------------------------------

    def heartbeat(self, agent_id: str) -> dict:
        """Send agent heartbeat."""
        return self._request("POST", f"/agents/{agent_id}/heartbeat")

    def get_agent(self, agent_id: str) -> dict:
        """Get agent details."""
        return self._request("GET", f"/agents/{agent_id}")

    def register_agent(self, name: str, agent_id: Optional[str] = None) -> dict:
        """Register a new agent."""
        body = {"name": name}
        if agent_id:
            body["id"] = agent_id
        return self._request("POST", "/agents", body)

    # ------------------------------------------
    # Bond
    # ------------------------------------------

    def create_bond(self, agent_id: str, amount: float, currency: str = "USD") -> dict:
        """Create a financial bond for an agent."""
        return self._request("POST", f"/agents/{agent_id}/bond", {
            "amount": amount,
            "currency": currency,
        })

    def get_bond(self, agent_id: str) -> Optional[Bond]:
        """Get bond status for an agent."""
        resp = self._request("GET", f"/agents/{agent_id}/bond")
        b = resp.get("bond")
        if not b:
            return None
        return Bond(
            id=b["id"],
            agent_id=b["agentId"],
            amount=b["amount"],
            balance=b["balance"],
            currency=b["currency"],
            status=b["status"],
            created_at=b["createdAt"],
            updated_at=b["updatedAt"],
        )

    def release_bond(self, agent_id: str) -> dict:
        """Release an agent's bond."""
        return self._request("DELETE", f"/agents/{agent_id}/bond")

    def slash_history(self, agent_id: str, limit: int = 50) -> list[dict]:
        """Get slash history for an agent."""
        return self._request("GET", f"/agents/{agent_id}/bond/slashes?limit={limit}").get("slashes", [])

    # ------------------------------------------
    # Events
    # ------------------------------------------

    def send_event(self, event_type: str, payload: dict, tenant_id: str = "default") -> dict:
        """Send a governance event."""
        return self._request("POST", "/events", {
            "type": event_type,
            "payload": payload,
            "tenantId": tenant_id,
        })

    # ------------------------------------------
    # Audit
    # ------------------------------------------

    def audit_export(self, limit: int = 100) -> list[dict]:
        """Export audit trail."""
        return self._request("GET", f"/audit?limit={limit}").get("entries", [])


# ==========================================
# Local Entropy (offline, no API call)
# ==========================================

import math


def calculate_entropy(text: str) -> EntropyResult:
    """Calculate Shannon entropy locally (no API call).

    Useful for offline/edge evaluation without calling ABS Core.
    """
    if not text:
        return EntropyResult(0, 0, 0, 0, False, 0)

    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    unique = len(freq)
    max_ent = math.log2(unique) if unique > 0 else 0
    ratio = entropy / max_ent if max_ent > 0 else 0

    patterns: list[str] = []
    if re.search(r"[A-Za-z0-9+/=]{20,}", text):
        patterns.append("base64_block")
    if re.search(r"(?:[0-9a-fA-F]{2}){10,}", text):
        patterns.append("hex_encoded")

    return EntropyResult(
        bits_per_char=entropy,
        payload_length=length,
        unique_chars=unique,
        max_entropy=max_ent,
        is_high_entropy=entropy > 4.5,
        normalized_ratio=ratio,
        detected_patterns=patterns,
    )


from .local_guard import (  # noqa: E402
    BUILTIN_PACKS,
    AbsGovernanceError,
    LocalPolicyEngine,
    guard_tool,
    guard_tools,
)
