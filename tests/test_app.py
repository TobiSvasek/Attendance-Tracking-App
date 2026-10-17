import re
from app import generate_session_token

def test_generate_session_token():
    """
    Test that generate_session_token returns a valid 64-character hex string.
    """
    token = generate_session_token()

    # 1. Check if token is a string
    assert isinstance(token, str)

    # 2. Check length (32 bytes = 64 hex characters)
    assert len(token) == 64

    # 3. Check if it contains only valid hexadecimal characters
    assert re.fullmatch(r"[0-9a-f]{64}", token) is not None
