import io
import json
from urllib.error import HTTPError
from unittest.mock import patch

import pytest

from abs_sdk import ABSClient
from abs_sdk.sentinel import Sentinel
from abs_sdk.types import Action


def _http_json_error(code: int, reason: str, body: dict) -> HTTPError:
    raw = json.dumps(body).encode("utf-8")
    return HTTPError(
        url="https://api.abscore.app/v1/mcp/tool-call",
        code=code,
        msg=reason,
        hdrs=None,
        fp=io.BytesIO(raw),
    )


def test_abs_client_raises_on_http_error_json_instead_of_failing_open():
    """SI-004: HTTP 401/404/503 JSON error payloads must NEVER default to ALLOW."""
    client = ABSClient(base_url="https://api.abscore.app/v1", token="bad-token")

    with patch("abs_sdk.urlopen", side_effect=_http_json_error(401, "Unauthorized", {"error": "invalid_token"})):
        with pytest.raises(RuntimeError, match="401"):
            client.evaluate_tool("fs.write", {"path": "/etc/passwd"})


def test_sentinel_checkpoint_fails_closed_on_http_error_json():
    """SI-004: Sentinel.checkpoint must return DENIED when gateway returns HTTP 503 JSON."""
    sentinel = Sentinel(api_key="tok", agent_id="agent-1", heartbeat_interval=0, base_url="https://api.abscore.app/v1")

    with patch("abs_sdk.urlopen", side_effect=_http_json_error(503, "Unavailable", {"error": "upstream_down"})):
        decision = sentinel.checkpoint(Action.EXECUTE, "shell/rm", {"cmd": "rm -rf /"})
        assert decision.verdict == "DENIED"


def test_abs_client_fails_closed_when_decision_field_missing():
    """SI-004: Missing decision field in HTTP 200 payload must default to DENY, never ALLOW."""
    client = ABSClient(base_url="https://api.abscore.app/v1", token="tok")

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"unexpected": true}'

    with patch("abs_sdk.urlopen", return_value=FakeResp()):
        verdict = client.evaluate_tool("db.query", {"sql": "DROP TABLE users"})
        assert verdict.decision == "DENY"
        assert verdict.policy_result.status == "DENIED"


def test_abs_client_parses_universal_gateway_authorize_envelope():
    """Supports local Universal Gateway /v1/authorize nested decision object."""
    client = ABSClient(base_url="http://127.0.0.1:8787/v1", token="local")

    class FakeGatewayResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({
                "trace_id": "trace-gw-1",
                "tool": "exec_command",
                "decision": {
                    "allowed": False,
                    "decision": "DENY",
                    "reason": "Blocked by local policy",
                    "policyReference": "local-deny-exec",
                },
            }).encode("utf-8")

    with patch("abs_sdk.urlopen", return_value=FakeGatewayResp()):
        verdict = client.evaluate_tool("exec_command", {"cmd": "rm -rf /"})
        assert verdict.decision == "DENY"
        assert verdict.policy_result.status == "DENIED"
        assert verdict.policy_result.reason == "Blocked by local policy"
        assert verdict.policy_result.policy_matched == "local-deny-exec"
        assert verdict.trace_id == "trace-gw-1"
