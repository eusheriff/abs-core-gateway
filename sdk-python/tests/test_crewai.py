import pytest
from unittest.mock import MagicMock
from abs_sdk.types import Action

# Mock CrewAI components for testing without requiring real CrewAI install if missing in CI,
# But we will supply a fake BaseTool wrapper if needed since we mock it.
class FakeDecision:
    def __init__(self, verdict, reason, rule_id, trace_id):
        self.verdict = verdict
        self.reason = reason
        self.rule_id = rule_id
        self.trace_id = trace_id

class FakeBaseTool:
    name = "fake_tool"
    description = "test tool"
    def _run(self, *args, **kwargs):
        return f"Executed with {args}"

def test_crewai_governance_decorator_allows():
    """Test CrewAI wrapper allows execution when ABS approves."""
    from abs_sdk.adapters.crewai import CrewAIGovernanceDecorator

    mock_sentinel = MagicMock()
    mock_sentinel.checkpoint.return_value = FakeDecision("ALLOWED", None, None, "123")

    decorator = CrewAIGovernanceDecorator(mock_sentinel)
    
    # We patch BaseTool module check inside crewai wrapper temporarily 
    import abs_sdk.adapters.crewai as cr
    cr.BaseTool = FakeBaseTool
    
    GovernedClass = decorator.guard_tool(FakeBaseTool)
    instance = GovernedClass()
    
    result = instance._run("test payload")
    
    # Assert ABS checkpoint was called
    mock_sentinel.checkpoint.assert_called_once_with(
        action=Action.EXECUTE,
        target="crewai/fake_tool",
        payload={"args": ("test payload",), "kwargs": {}, "tool": "fake_tool"}
    )
    
    # Assert logic flowed through because it was ALLOWED
    assert result == "Executed with ('test payload',)"


def test_crewai_governance_decorator_denies():
    """Test CrewAI wrapper blocks execution when ABS denies."""
    from abs_sdk.adapters.crewai import CrewAIGovernanceDecorator

    mock_sentinel = MagicMock()
    mock_sentinel.checkpoint.return_value = FakeDecision("DENIED", "Policy violation", "101", "123")

    decorator = CrewAIGovernanceDecorator(mock_sentinel)
    import abs_sdk.adapters.crewai as cr
    cr.BaseTool = FakeBaseTool
    
    GovernedClass = decorator.guard_tool(FakeBaseTool)
    instance = GovernedClass()
    
    result = instance._run("bad payload")
    
    mock_sentinel.checkpoint.assert_called_once()
    # It must block and return the error string instead of super._run
    assert "ABS Governance blocked" in result
    assert "Policy violation" in result
