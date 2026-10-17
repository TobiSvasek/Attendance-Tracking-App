import unittest
import os
from werkzeug.security import check_password_hash

# Mock environment variables needed by app.py
os.environ['SECRET_KEY'] = 'test-secret'
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['MAIL_SERVER'] = 'localhost'
os.environ['MAIL_PORT'] = '587'
os.environ['MAIL_USE_SSL'] = 'false'
os.environ['MAIL_USERNAME'] = 'test'
os.environ['MAIL_PASSWORD'] = 'test'
os.environ['MAIL_DEFAULT_SENDER'] = 'test@example.com'

from app import Employee

class TestEmployee(unittest.TestCase):

    def setUp(self):
        self.employee = Employee(email="test@example.com")

    def test_set_password_creates_hash(self):
        """Test that set_password creates a hash and not plaintext"""
        password = "SecurePassword123"
        self.employee.set_password(password)

        self.assertIsNotNone(self.employee.password_hash)
        self.assertNotEqual(self.employee.password_hash, password)
        self.assertTrue(self.employee.password_hash.startswith("scrypt:") or self.employee.password_hash.startswith("pbkdf2:"))

    def test_check_password_correct(self):
        """Test check_password returns True for the correct password"""
        password = "SecurePassword123"
        self.employee.set_password(password)

        self.assertTrue(self.employee.check_password(password))

    def test_check_password_incorrect(self):
        """Test check_password returns False for an incorrect password"""
        password = "SecurePassword123"
        self.employee.set_password(password)

        self.assertFalse(self.employee.check_password("WrongPassword456"))
        self.assertFalse(self.employee.check_password("securepassword123"))

    def test_password_salting(self):
        """Test that hashing the same password twice yields different hashes due to salting"""
        password = "SecurePassword123"

        self.employee.set_password(password)
        hash1 = self.employee.password_hash

        # Create another employee to reset the hash properly for testing salting
        employee2 = Employee(email="test2@example.com")
        employee2.set_password(password)
        hash2 = employee2.password_hash

        self.assertNotEqual(hash1, hash2)

if __name__ == "__main__":
    unittest.main()
