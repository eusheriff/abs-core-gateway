from typing import Any, Dict, Optional, Type
import logging

from abs_sdk.sentinel import Sentinel
from abs_sdk.types import Action

logger = logging.getLogger(__name__)

class LangChainGovernanceDecorator:
    """
    ABS Core pre-dispatch governance wrapper for LangChain tools.
    Hooks into LangChain BaseTool._run to evaluate arguments against the
    ABS Engine before the tool execution occurs.
    """

    def __init__(self, sentinel: Sentinel):
        self.sentinel = sentinel

    def guard_tool(self, original_tool_cls: Any, action_type: Action = Action.EXECUTE) -> Any:
        sentinel = self.sentinel

        class GovernedLangChainTool(original_tool_cls):
            def _run(self, *args: Any, **kwargs: Any) -> Any:
                tool_name = getattr(self, "name", "unknown_tool")
                payload = {
                    "args": args,
                    "kwargs": kwargs,
                    "tool": tool_name
                }
                logger.debug(f"[ABS] Evaluating LangChain Tool: {tool_name}")

                decision = sentinel.checkpoint(
                    action=action_type,
                    target=f"langchain/{tool_name}",
                    payload=payload
                )

                if decision.verdict != "ALLOWED":
                    msg = f"ABS Governance blocked LangChain tool [{tool_name}]. Reason: {decision.reason} | Rule: {decision.rule_id}"
                    logger.warning(msg)
                    raise PermissionError(msg)

                logger.info(f"[ABS] LangChain tool [{tool_name}] approved.")
                return super()._run(*args, **kwargs)

        GovernedLangChainTool.__name__ = f"Governed_{getattr(original_tool_cls, '__name__', 'Tool')}"
        return GovernedLangChainTool
