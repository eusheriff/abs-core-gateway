# `abs-core` — ABS Core Python SDK

[![PyPI](https://img.shields.io/pypi/v/abs-core)](https://pypi.org/project/abs-core/)

Official Python SDK for [ABS Core](https://github.com/eusheriff/abs-core-gateway) — Deterministic Runtime Governance & Cryptographic Non-Repudiation for AI Agents.

## Installation

```bash
pip install abs-core
# or
uv add abs-core
```

*(Python import package: `abs_sdk`)*

---

## 1-Line Tool Guard (Zero-Daemon Local Mode)

Works **in-process** with zero external dependencies and no daemon required — compatible with **LangChain, LangGraph, CrewAI, OpenAI Agents, PydanticAI**, and plain Python functions:

```python
from abs_sdk import guard_tools, guard_tool, AbsGovernanceError

# Wrap a list of LangChain / LangGraph / CrewAI tools in 1 line
tools = guard_tools(tools, pack="devsecops")  # packs: devsecops | fintech-pix | lgpd-health

# Or wrap a single Python function with local hash-chained audit logging
safe_shell = guard_tool(run_shell, name="system.exec", pack="devsecops", audit_path=".abs/audit.ndjson")
```

Use `shadow=True` to log `SHADOW_DENY` receipts without blocking execution during rollout.

---

## Direct Local Policy Evaluation

```python
from abs_sdk import LocalPolicyEngine

engine = LocalPolicyEngine(pack="fintech-pix", audit_path=".abs/audit.ndjson")
result = engine.evaluate("pix.transfer", {"amount": 50000})
# result["decision"] == "ESCALATE", result["allowed"] is False, result["receipt_hash"] == sha256(...)
```

---

## Remote / Local Universal Gateway Client (`ABSClient`)

Connect to a running ABS Core Universal Gateway (`127.0.0.1:8787` or cloud DSN) with fail-closed SI-004 enforcement:

```python
from abs_sdk import ABSClient

client = ABSClient(
    dsn="http://127.0.0.1:8787",
    token="abs_pat_xxx",
)

verdict = client.evaluate_tool("fs.write", {
    "path": "/etc/passwd",
    "content": "malicious",
})

if verdict.decision != "ALLOW":
    raise PermissionError(f"Blocked by ABS: {verdict.policy_result.reason}")
```

## Features

- **Zero-Daemon Local Engine (`LocalPolicyEngine`)**: In-process evaluation against `.abs/policy.json` or built-in packs (`devsecops`, `fintech-pix`, `lgpd-health`) with SHA-256 receipts.
- **1-Line Framework Wrappers (`guard_tool`, `guard_tools`)**: Drop-in support for LangChain, LangGraph, CrewAI, OpenAI Agents, PydanticAI, and plain callables.
- **Fail-Closed Gateway Client (`ABSClient`)**: Enforces SI-004 fail-closed semantics on network/HTTP/JSON errors.
- **Zero Dependencies**: Pure Python stdlib (`urllib`, `json`, `hashlib`, `re`, `math`).

## License

MIT — [ABS Core Repository](https://github.com/eusheriff/abs-core-gateway)
