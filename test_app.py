import pytest
from app import is_strong_password

@pytest.mark.parametrize(
    "password, expected",
    [
        # Valid passwords
        ("Password123", True),
        ("StrongPass1!", True),
        ("aA1!2345", True),
        # Too short (length < 8)
        ("Aa1", False),
        ("Short1", False),
        ("Pas1234", False),
        # No uppercase
        ("password123", False),
        ("abcde123", False),
        ("lowercase1", False),
        # No lowercase
        ("PASSWORD123", False),
        ("ABCDE123", False),
        ("UPPERCASE1", False),
        # No numbers
        ("PasswordABC", False),
        ("OnlyLetters", False),
        ("NoNumberHere", False),
        # Empty string
        ("", False),
    ]
)
def test_is_strong_password(password, expected):
    assert is_strong_password(password) == expected
