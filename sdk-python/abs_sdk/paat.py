import jwt
from typing import List, Dict, Any, Optional

from .types import Policy


class PAATPayload:
    """PAATPayload mapped dict keys structure."""
    
    @staticmethod
    def create(policies: List[Policy], issuer: str = 'abs-core', subject: Optional[str] = None) -> Dict[str, Any]:
        payload = {
            "iss": issuer,
            "policies": [
                {k: v for k, v in p.__dict__.items() if v is not None} 
                for p in policies
            ]
        }
        if subject:
            payload["sub"] = subject
        return payload


def create_paat(
    policies: List[Policy],
    private_key_pem: str,
    issuer: str = 'abs-core',
    subject: Optional[str] = None
) -> str:
    """
    Generates a Policy-as-a-Token (PAAT) string embedded with the provided policies.
    Employs RSA signature (RS256).
    """
    payload = PAATPayload.create(policies, issuer, subject)
    
    # We let PyJWT handle `iat` (issued at) via default fields if needed, 
    # but to be safe and match TS we will add exp and iat?
    import time
    now = int(time.time())
    payload["iat"] = now
    # 1 year expiration
    payload["exp"] = now + (365 * 24 * 60 * 60)

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")
    return token


def verify_paat(token: str, public_key_pem: str) -> List[Policy]:
    """
    Validates a Policy-as-a-Token (PAAT) using the issuer's public key.
    """
    try:
        decoded = jwt.decode(token, public_key_pem, algorithms=["RS256"])
    except Exception as e:
        raise ValueError(f"Invalid PAAT signature or expired: {str(e)}")

    if "policies" not in decoded or not isinstance(decoded["policies"], list):
        raise ValueError("Invalid PAAT payload: missing or malformed policies array.")

    return [Policy(**p) for p in decoded["policies"]]


def create_cat(
    payload_data: Dict[str, Any],
    private_key_pem: str,
    issuer: str = 'abs-core'
) -> str:
    """
    Generates a Compliance Attestation Token (CAT) containing proof of execution.
    """
    import time
    now = int(time.time())
    
    payload = {**payload_data}
    payload["iss"] = issuer
    payload["iat"] = now
    payload["exp"] = now + (365 * 24 * 60 * 60)

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")
    return token


def verify_cat(token: str, public_key_pem: str) -> Dict[str, Any]:
    """
    Validates a Compliance Attestation Token (CAT) using the issuer's public key.
    """
    try:
        decoded = jwt.decode(token, public_key_pem, algorithms=["RS256"])
    except Exception as e:
        raise ValueError(f"Invalid CAT signature or expired: {str(e)}")

    if not decoded.get("agentId") or not decoded.get("proofHash"):
        raise ValueError("Invalid CAT payload: missing critical execution identity fields.")

    return decoded
