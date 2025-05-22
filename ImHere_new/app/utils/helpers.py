import secrets
import string
import hashlib
from flask import session, request, redirect, url_for
from app.models.employee import Employee

def go_back():
    """Returns a script to navigate back in browser history"""
    return "<script>window.history.back();</script>", 200

def generate_session_token():
    """Generates a secure random token for session authentication"""
    return secrets.token_hex(32)

def is_valid_session():
    """Checks if the current session is valid"""
    employee_id = session.get('employee_id')
    session_token = session.get('session_token')

    if not employee_id or not session_token:
        return False

    employee = Employee.query.get(employee_id)
    if not employee or employee.session_token != session_token:
        return False

    return True

def restrict_ip(allowed_ips):
    """Decorator to restrict access to certain IPs"""
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def wrapped(*args, **kwargs):
            print("IP check running")
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            print("Client IP:", client_ip)
            if client_ip not in allowed_ips:
                return go_back()
            return f(*args, **kwargs)
        return wrapped
    return decorator

def generate_random_password(length=12):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def allowed_file(filename):
    """Check if uploaded file has an allowed extension"""
    from flask import current_app
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hash_uid(uid):
    """Hash a UID using SHA-256"""
    return hashlib.sha256(uid.encode()).hexdigest()
