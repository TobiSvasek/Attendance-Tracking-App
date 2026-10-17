import re
import unittest
import string
import pytest
from app import (
    generate_session_token,
    allowed_file,
    is_strong_password,
    generate_random_password
)

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


@pytest.mark.parametrize("filename, expected", [
    # Valid extensions
    ("image.png", True),
    ("photo.jpg", True),
    ("picture.jpeg", True),
    ("animation.gif", True),

    # Uppercase extensions
    ("IMAGE.PNG", True),
    ("PHOTO.JPG", True),

    # Invalid extensions
    ("document.txt", False),
    ("script.py", False),
    ("archive.zip", False),
    ("executable.exe", False),

    # No extension
    ("filename", False),
    ("filename.", False),

    # Multiple dots
    ("archive.tar.gz", False),
    ("my.image.png", True),

    # Hidden files
    (".hidden", False),
    (".hidden.png", True),
])
def test_allowed_file(filename, expected):
    assert allowed_file(filename) == expected


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


class TestGenerateRandomPassword(unittest.TestCase):
    def test_default_length(self):
        password = generate_random_password()
        self.assertEqual(len(password), 12)

    def test_custom_length(self):
        for length in [8, 16, 100, 0, 1]:
            password = generate_random_password(length)
            self.assertEqual(len(password), length)

    def test_character_distribution(self):
        password = generate_random_password(1000)
        alphabet = string.ascii_letters + string.digits + string.punctuation
        for char in password:
            self.assertIn(char, alphabet)

    def test_randomness(self):
        password_1 = generate_random_password()
        password_2 = generate_random_password()
        self.assertNotEqual(password_1, password_2)
