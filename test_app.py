import unittest
import string
from app import generate_random_password

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

if __name__ == '__main__':
    unittest.main()
