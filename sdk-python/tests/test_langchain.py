import pytest
from unittest.mock import MagicMock
from abs_sdk.types import Action
from abs_sdk.adapters.langchain import LangChainGovernanceDecorator

class FakeDecision:
    def __init__(self, verdict, reason, rule_id, trace_id):
        self.verdict = verdict
        self.reason = reason
        self.rule_id = rule_id
        self.trace_id = trace_id

class BaseFakeTool:
    name = "db_query"
    def _run(self, query):
        return f"Executed query: {query}"

def test_langchain_governance_decorator_allows():
    mock_sentinel = MagicMock()
    mock_sentinel.checkpoint.return_value = FakeDecision("ALLOWED", None, None, "trace-123")

    decorator = LangChainGovernanceDecorator(mock_sentinel)
    GovernedToolClass = decorator.guard_tool(BaseFakeTool)
    tool = GovernedToolClass()

    result = tool._run("SELECT * FROM users")
    assert result == "Executed query: SELECT * FROM users"
    mock_sentinel.checkpoint.assert_called_once_with(
        action=Action.EXECUTE,
        target="langchain/db_query",
        payload={"args": ("SELECT * FROM users",), "kwargs": {}, "tool": "db_query"}
    )

def test_langchain_governance_decorator_denies():
    mock_sentinel = MagicMock()
    mock_sentinel.checkpoint.return_value = FakeDecision("DENIED", "Prohibited SQL DROP", "rule-99", "trace-999")

    decorator = LangChainGovernanceDecorator(mock_sentinel)
    GovernedToolClass = decorator.guard_tool(BaseFakeTool)
    tool = GovernedToolClass()

    with pytest.raises(PermissionError) as exc_info:
        tool._run("DROP TABLE users")

    assert "Prohibited SQL DROP" in str(exc_info.value)
