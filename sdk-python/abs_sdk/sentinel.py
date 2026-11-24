import os
import threading
import time
from typing import Any, Dict, Optional

from . import ABSClient
from .types import Action

class Sentinel:
    """Sentinel SDK - High-level AI Agent Governance.

    Provides richer control over ABS Core features: custom policies, per-action checkpoints,
    heartbeats, and token budget management based on the ABS Protocol.
    """

    def __init__(
        self,
        api_key: str,
        agent_id: str,
        heartbeat_interval: int = 60,
        base_url: Optional[str] = None
    ):
        """
        Initializes the Sentinel instance.

        Args:
            api_key: The Personal Access Token (PAT) for ABS Core.
            agent_id: The ID of your agent.
            heartbeat_interval: Heartbeat pulse interval in seconds.
            base_url: Optional base url overriding 'https://api.abscore.app/v1'.
        """
        self.api_key = api_key
        self.agent_id = agent_id
        self.heartbeat_interval = heartbeat_interval

        _base_url = base_url or os.environ.get("ABS_BASE_URL", "https://api.abscore.app/v1")
        self.client = ABSClient(base_url=_base_url, token=self.api_key)
        
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._stop_heartbeat = threading.Event()

    def init(self):
        """
        Activates Sentinel logic. 
        Will start standard heartbeat threads for constant telemetry connection.
        """
        # We start the background thread only if heartbeat is configured logically.
        if self.heartbeat_interval > 0:
            self._stop_heartbeat.clear()
            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self._heartbeat_thread.start()
            
        # Do initial registration check
        try:
            self.client.get_agent(self.agent_id)
        except Exception:
            # Try to register if it fails
            try:
                self.client.register_agent(name=f"Agent {self.agent_id}", agent_id=self.agent_id)
            except Exception:
                pass


    def _heartbeat_loop(self):
        """Background thread sending agent presence info."""
        while not self._stop_heartbeat.is_set():
            try:
                self.client.heartbeat(self.agent_id)
            except Exception:
                pass
            self._stop_heartbeat.wait(self.heartbeat_interval)

    def stop(self):
        """Stops the Sentinel services (like heartbeats)."""
        self._stop_heartbeat.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)

    def checkpoint(
        self,
        action: Action,
        target: str,
        payload: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Any:  
        """
        Runs a governance checkpoint evaluating logic before proceeding with operation.

        Args:
            action: Action class parameter (e.g. Action.WRITE)
            target: Destination string/uri targeted by the action.
            payload: Standard payload dictionary argument.
            context: Context attributes like 'userId', 'environment'.

        Returns:
            The decision dict parsed from ABS API containing 'verdict', 'reason', etc.
        """
        full_args = {
            "action": action.value,
            "target": target,
            "data": payload,
            "context": context or {}
        }
        
        # Use underlying ABSClient MCP generic tool eval endpoint to execute the checkpoint internally
        # You could also use a dedicated Sentinel API endpoint if designed as such, but evaluating a pseudo-tool
        # works uniformly for checkpoints.
        
        try:
            verdict = self.client.evaluate_tool(
                tool_name="sentinel.checkpoint",
                arguments=full_args,
                agent_id=self.agent_id
            )
            
            # Pack mapping structure as documented: decision.verdict, decision.reason
            class Decision:
                def __init__(self, v):
                    self.verdict = v.decision if v.decision == 'ALLOW' else "ALLOWED" if v.decision == 'ALLOW' else v.decision
                    
                    if self.verdict == "ALLOW":
                        self.verdict = "ALLOWED"
                    elif self.verdict == "DENY":
                        self.verdict = "DENIED"
                        
                    self.reason = getattr(v.policy_result, 'reason', None) or "No reason provided"
                    self.rule_id = getattr(v.policy_result, 'policy_matched', None)
                    self.trace_id = v.trace_id

            return Decision(verdict)
            
        except Exception as e:
            class BlockedDecision:
                verdict = "DENIED"
                reason = f"Checkpoint Error: {str(e)}"
                rule_id = "SYS-ERR"
                trace_id = None
            return BlockedDecision()

