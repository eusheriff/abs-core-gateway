# mypy: ignore-errors
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import List, Dict, Any

from abs_sdk.types import Policy
from abs_sdk.paat import create_paat, verify_paat, create_cat, verify_cat


@pytest.fixture
def rsa_key_pair():
    """Generates an RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem


def test_paat_generation_and_verification(rsa_key_pair):
    """Test generating a PAAT token and successfully verifying it."""
    private_key, public_key = rsa_key_pair
    
    policies: List[Policy] = [
        Policy(name="No PII", action="DENY", risk=0.5)
    ]
    
    # Encode PAAT
    token = create_paat(
        policies=policies,
        private_key_pem=private_key,
        issuer="abs-test"
    )
    
    assert isinstance(token, str)
    assert len(token) > 0
    
    # Decode PAAT
    decoded_policies = verify_paat(token, public_key)
    assert len(decoded_policies) == 1
    assert decoded_policies[0].name == "No PII"
    assert decoded_policies[0].action == "DENY"

def test_cat_generation_and_verification(rsa_key_pair):
    """Test generating a CAT token and successfully verifying it."""
    private_key, public_key = rsa_key_pair
    
    payload_data = {
        "agentId": "test-agent-1",
        "toolName": "finance.write",
        "verdict": "ALLOW",
        "proofHash": "sha256:1234abcd"
    }
    
    # Encode CAT
    token = create_cat(
        payload_data=payload_data,
        private_key_pem=private_key,
        issuer="abs-guard"
    )
    
    assert isinstance(token, str)
    assert len(token) > 0
    
    # Decode CAT
    decoded = verify_cat(token, public_key)
    assert decoded["agentId"] == "test-agent-1"
    assert decoded["proofHash"] == "sha256:1234abcd"
    assert decoded["iss"] == "abs-guard"
