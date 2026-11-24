import json
import pytest
from abs_sdk import AbsGovernanceError, LocalPolicyEngine, guard_tool, guard_tools


def test_local_policy_engine_blocks_denied_and_seals_receipt(tmp_path):
    audit_file = tmp_path / "audit.ndjson"
    engine = LocalPolicyEngine(pack="devsecops", audit_path=audit_file)

    allow = engine.evaluate("fs.read", {"path": "README.md"})
    assert allow["allowed"] is True
    assert allow["decision"] == "ALLOW"

    deny_secret = engine.evaluate("fs.read", {"path": ".env"})
    assert deny_secret["allowed"] is False
    assert deny_secret["decision"] == "DENY"

    deny_tool = engine.evaluate("system.exec", {"cmd": "rm -rf /"})
    assert deny_tool["allowed"] is False
    assert deny_tool["decision"] == "DENY"

    lines = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 3
    assert all(len(r["receipt_hash"]) == 64 for r in lines)


def test_guard_tools_wraps_plain_callables_and_langchain_style_tools():
    executed = []

    def safe_read(path: str) -> str:
        executed.append(("safe_read", path))
        return f"content:{path}"

    def dangerous_shell(cmd: str) -> str:
        executed.append(("shell", cmd))
        return "should_never_run"

    class FakeLangChainTool:
        name = "pix.transfer"

        def invoke(self, payload: dict) -> str:
            executed.append(("pix.transfer", payload))
            return "transferred"

    guarded_safe = guard_tool(safe_read, name="fs.read", pack="devsecops")
    guarded_shell = guard_tool(dangerous_shell, name="system.exec", pack="devsecops")
    guarded_list = guard_tools([FakeLangChainTool()], pack="fintech-pix")

    assert guarded_safe(path="README.md") == "content:README.md"

    with pytest.raises(AbsGovernanceError):
        guarded_shell(cmd="rm -rf /")

    with pytest.raises(AbsGovernanceError):
        guarded_list[0].invoke({"amount": 50000})

    assert executed == [("safe_read", "README.md")]


def test_shadow_mode_allows_execution_while_logging_shadow_deny(tmp_path):
    audit_file = tmp_path / "shadow.ndjson"

    def shell(cmd: str) -> str:
        return f"ran:{cmd}"

    guarded = guard_tool(shell, name="system.exec", pack="devsecops", shadow=True, audit_path=audit_file)
    assert guarded(cmd="whoami") == "ran:whoami"
    rec = json.loads(audit_file.read_text(encoding="utf-8").strip())
    assert rec["decision"] == "SHADOW_DENY"
    assert rec["would_block"] is True
