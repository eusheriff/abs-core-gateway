from typing import Any, Callable, Dict, Optional, Type
import logging

try:
    from crewai.tools import BaseTool
except ImportError:
    BaseTool = None

from abs_sdk import ABSClient
from abs_sdk.sentinel import Sentinel
from abs_sdk.types import Action

logger = logging.getLogger(__name__)

class CrewAIGovernanceDecorator:
    """
    ABS Core governance wrapper for CrewAI.
    Hooks into CrewAI BaseTool to validate inputs against the ABS Engine
    before executing the core tool action.
    """

    def __init__(self, sentinel: Sentinel):
        self.sentinel = sentinel

    def guard_tool(self, original_tool: Type[BaseTool], action_type: Action = Action.EXECUTE) -> Type[BaseTool]:
        """
        Wraps a CrewAI BaseTool class modifying its _run logic dynamically
        to ask ABS Core permission first.
        """
        if not BaseTool:
            raise ImportError("crewai is not installed. Please install it using `pip install crewai`.")

        class GovernedTool(original_tool):  # type: ignore
            # Preserve metadata
            name: str = getattr(original_tool, "name", "unknown_tool")
            description: str = getattr(original_tool, "description", "Governed tool")

            def _run(self, *args: Any, **kwargs: Any) -> Any:
                
                # Check point payload
                payload = {
                    "args": args,
                    "kwargs": kwargs,
                    "tool": self.name
                }

                logger.debug(f"[ABS] Evaluating CrewAI Tool Execution: {self.name}")

                decision = self._abs_sentinel.checkpoint(
                    action=self._abs_action,
                    target=f"crewai/{self.name}",
                    payload=payload,
                )

                if decision.verdict != "ALLOWED":
                    msg = f"ABS Governance blocked tool execution [{self.name}]. Reason: {decision.reason} | Rule: {decision.rule_id}"
                    logger.warning(msg)
                    return f"Error: {msg}"
                
                logger.info(f"[ABS] Tool execution {self.name} approved. Proceeding.")
                return super()._run(*args, **kwargs)

        # Inject references
        GovernedTool._abs_sentinel = self.sentinel
        GovernedTool._abs_action = action_type

        return GovernedTool


def with_governance(sentinel: Sentinel, action: Action = Action.EXECUTE):
    """
    Decorator approach for standard python function tools within CrewAI wrappers if needed.
    """
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            payload = {"args": args, "kwargs": kwargs, "function": func.__name__}
            decision = sentinel.checkpoint(action, f"crewai/func/{func.__name__}", payload)
            
            if decision.verdict != "ALLOWED":
                return f"Error: ABS Governance blocked execution. Reason: {decision.reason}"
                
            return func(*args, **kwargs)
        return wrapper
    return decorator
