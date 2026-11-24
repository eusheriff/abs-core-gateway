"""
1-line Python governance adapters & zero-daemon local policy engine for `abs-core`.

Works out-of-the-box with:
- Plain Python callables & OpenAI Agents / PydanticAI tools
- LangChain / LangGraph tools (objects exposing `.invoke` / `.run` / `._run`)
- CrewAI tools
"""

from __future__ import annotations

import fnmatch
import functools
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Union

BUILTIN_PACKS: Dict[str, Dict[str, Any]] = {
    "devsecops": {
        "id": "sovereign-devsecops",
        "deny_tools": [
            "system.exec",
            "system.shell",
            "fs.rmdir_root*",
            "git.push_force_main*",
            "cloud.destroy_cluster*",
        ],
        "escalate_tools": [
            "deploy.production*",
            "k8s.apply_prod*",
            "terraform.apply*",
            "npm.publish*",
            "db.migrate_prod*",
        ],
        "arg_restrictions": {
            "exec_command": {
                "cmd": r"deny:rm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|~|\*)|mkfs|dd\s+if=|chmod\s+-R\s+777|(curl|wget).*\|\s*(sh|bash|zsh)",
            },
            "fs.read": {"path": r"deny:(\.ssh/id_|/etc/shadow|(^|/)\.env$)"},
            "fs.write": {"path": r"deny:(\.ssh/authorized_keys|/etc/|\.\./)"},
        },
    },
    "fintech-pix": {
        "id": "bacen-fintech-pix",
        "deny_tools": [
            "system.exec",
            "system.shell",
            "exec_command",
            "fs.delete*",
            "db.drop*",
            "vault.export_raw_key*",
            "auth.disable_2fa*",
        ],
        "escalate_tools": [
            "pix.transfer*",
            "pix.key_register*",
            "pix.key_delete*",
            "wire.transfer*",
            "ledger.reverse*",
            "credit.limit_override*",
            "db.migrate*",
        ],
        "arg_restrictions": {
            "db.query": {
                "sql": r"deny:DROP|TRUNCATE|ALTER\s+TABLE|DELETE\s+FROM\s+(accounts|ledgers|pix_keys|audit_logs)",
            },
            "fs.read": {"path": r"deny:\.env|\.pem|\.key|id_rsa|/etc/passwd|/etc/shadow"},
            "fs.write": {"path": r"deny:/etc|/sys|/proc|\.\./|migrations/"},
        },
    },
    "lgpd-health": {
        "id": "lgpd-healthcare",
        "deny_tools": [
            "system.exec",
            "system.shell",
            "exec_command",
            "ehr.bulk_export_unmasked*",
            "db.drop*",
            "storage.make_public*",
        ],
        "escalate_tools": [
            "lgpd.cryptographic_erasure*",
            "ehr.share_external*",
            "patient.delete*",
            "consent.override*",
        ],
        "arg_restrictions": {
            "db.query": {"sql": r"deny:DROP|TRUNCATE|SELECT\s+\*\s+FROM\s+patients(?!.*LIMIT)"},
            "http.post": {"body": r"deny:\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"},
            "fs.read": {"path": r"deny:\.env|\.pem|\.key|dicom_raw_phi"},
        },
    },
}


class AbsGovernanceError(PermissionError):
    """Raised when an AI agent tool call is denied or escalated by ABS Core."""

    def __init__(self, decision: Dict[str, Any]):
        self.decision = decision
        super().__init__(
            f"[ABS Core {decision.get('decision', 'DENY')}] "
            f"{decision.get('reason', 'Blocked by policy')} "
            f"(receipt: {decision.get('receipt_hash', '')[:16]})"
        )


class LocalPolicyEngine:
    """Zero-daemon, in-process deterministic policy evaluator with SI-001 receipt sealing."""

    def __init__(
        self,
        policy: Optional[Union[Dict[str, Any], str, Path]] = None,
        pack: Optional[str] = None,
        shadow: bool = False,
        audit_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.shadow = shadow
        self.audit_path = Path(audit_path) if audit_path else None
        self.policy = self._load_policy(policy=policy, pack=pack)

    @staticmethod
    def _load_policy(
        policy: Optional[Union[Dict[str, Any], str, Path]],
        pack: Optional[str],
    ) -> Dict[str, Any]:
        if isinstance(policy, dict):
            return policy
        if isinstance(policy, Path):
            return json.loads(policy.read_text(encoding="utf-8"))
        if isinstance(policy, str):
            trimmed = policy.strip()
            if trimmed.startswith("{"):
                return json.loads(trimmed)
            return json.loads(Path(trimmed).read_text(encoding="utf-8"))
        if pack:
            key = pack.strip().lower()
            if key not in BUILTIN_PACKS:
                raise ValueError(f"Unknown ABS policy pack '{pack}'. Available: {', '.join(BUILTIN_PACKS)}")
            return BUILTIN_PACKS[key]
        default_file = Path.cwd() / ".abs" / "policy.json"
        if default_file.exists():
            return json.loads(default_file.read_text(encoding="utf-8"))
        return BUILTIN_PACKS["devsecops"]

    def evaluate(self, tool_name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        args_dict = args if isinstance(args, dict) else {"input": args}
        decision = "ALLOW"
        reason = "Allowed by local policy"

        for pattern in self.policy.get("deny_tools", []):
            if fnmatch.fnmatch(tool_name, pattern):
                decision = "DENY"
                reason = f'Tool "{tool_name}" is blocked by policy (pattern: {pattern})'
                break

        if decision == "ALLOW":
            for pattern in self.policy.get("escalate_tools", []):
                if fnmatch.fnmatch(tool_name, pattern):
                    decision = "ESCALATE"
                    reason = f'Tool "{tool_name}" requires human approval (pattern: {pattern})'
                    break

        if decision == "ALLOW":
            restrictions = self.policy.get("arg_restrictions", {}).get(tool_name, {})
            for arg_key, rule in restrictions.items():
                if arg_key in args_dict and isinstance(rule, str) and rule.startswith("deny:"):
                    regex = rule[len("deny:"):]
                    if re.search(regex, str(args_dict[arg_key])):
                        decision = "DENY"
                        reason = f'Argument "{arg_key}" on "{tool_name}" violated policy restriction'
                        break

        would_block = decision != "ALLOW"
        effective_decision = (
            ("SHADOW_DENY" if would_block else "SHADOW_ALLOW") if self.shadow else decision
        )
        allowed = True if self.shadow else (not would_block)

        record: Dict[str, Any] = {
            "schema": "abs-python-local-receipt/v1",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "policy_id": self.policy.get("id", "local-policy"),
            "tool": tool_name,
            "mode": "shadow" if self.shadow else "enforce",
            "decision": effective_decision,
            "allowed": allowed,
            "would_block": would_block,
            "reason": reason,
        }
        record["receipt_hash"] = hashlib.sha256(
            json.dumps(record, sort_keys=True).encode("utf-8")
        ).hexdigest()

        if self.audit_path is not None:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")

        return record


def guard_tool(
    tool: Any,
    *,
    name: Optional[str] = None,
    pack: Optional[str] = None,
    policy: Optional[Union[Dict[str, Any], str, Path]] = None,
    shadow: bool = False,
    audit_path: Optional[Union[str, Path]] = None,
) -> Any:
    """Wrap a single callable or LangChain/LangGraph/CrewAI tool with 1-line ABS governance."""
    engine = LocalPolicyEngine(policy=policy, pack=pack, shadow=shadow, audit_path=audit_path)
    tool_name = name or getattr(tool, "name", None) or getattr(tool, "__name__", "unknown.tool")

    def _check(call_args: tuple, call_kwargs: dict) -> None:
        payload: Dict[str, Any] = dict(call_kwargs)
        if call_args:
            if len(call_args) == 1 and isinstance(call_args[0], dict):
                payload.update(call_args[0])
            else:
                payload["args"] = list(call_args)
        result = engine.evaluate(tool_name, payload)
        if not result["allowed"]:
            raise AbsGovernanceError(result)

    # Plain Python function / OpenAI Agents / PydanticAI tool
    if callable(tool) and not hasattr(tool, "invoke") and not hasattr(tool, "_run"):
        @functools.wraps(tool)
        def wrapped_fn(*args: Any, **kwargs: Any) -> Any:
            _check(args, kwargs)
            return tool(*args, **kwargs)

        return wrapped_fn

    # Framework tool object (LangChain / LangGraph / CrewAI)
    class _GuardedToolProxy:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def __getattr__(self, item: str) -> Any:
            return getattr(self._inner, item)

        def invoke(self, input_data: Any, *args: Any, **kwargs: Any) -> Any:
            _check((input_data,), kwargs)
            return self._inner.invoke(input_data, *args, **kwargs)

        def run(self, *args: Any, **kwargs: Any) -> Any:
            _check(args, kwargs)
            return self._inner.run(*args, **kwargs)

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            _check(args, kwargs)
            return self._inner._run(*args, **kwargs)

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            _check(args, kwargs)
            return self._inner(*args, **kwargs)

    return _GuardedToolProxy(tool)


def guard_tools(
    tools: Sequence[Any],
    *,
    pack: Optional[str] = "devsecops",
    policy: Optional[Union[Dict[str, Any], str, Path]] = None,
    shadow: bool = False,
    audit_path: Optional[Union[str, Path]] = None,
) -> List[Any]:
    """Wrap a list of tools (LangChain, LangGraph, CrewAI, or plain callables) in 1 line."""
    return [
        guard_tool(t, pack=pack, policy=policy, shadow=shadow, audit_path=audit_path)
        for t in tools
    ]
