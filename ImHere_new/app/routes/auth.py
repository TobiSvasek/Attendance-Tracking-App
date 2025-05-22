from flask import Blueprint, request, redirect, render_template, url_for, session, make_response
from app.models.employee import Employee, is_strong_password
from app import db, limiter
from flask_limiter.errors import RateLimitExceeded
from app.utils.helpers import generate_session_token, allowed_file
from app.utils.email import send_reset_email, send_set_details_email
from urllib.parse import urlsplit
from datetime import datetime
import os
import secrets

# Create a blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

def custom_login_key():
    if request.method == 'POST':
        return f"{request.remote_addr}:{request.form.get('email', '')}"
    return request.remote_addr

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    message = request.args.get('message')

    if request.method == 'POST':
        try:
            # Apply rate limiting here
            limiter.limit("5 per minute", key_func=custom_login_key)(lambda: None)()
        except RateLimitExceeded as e:
            return render_template("429.html", retry_after=int(e.description.split(' ')[-1]) if "Retry-After" in e.description else 60), 429

        # Continue with login logic
        email = request.form['email']
        password = request.form['password']
        employee = Employee.query.filter_by(email=email).first()

        if employee and employee.check_password(password):
            token = generate_session_token()
            employee.session_token = token
            db.session.commit()

            session['employee_id'] = employee.id
            session['session_token'] = token
            session['login_time'] = datetime.now().timestamp()

            next_page = request.args.get('next')
            if not next_page or urlsplit(next_page).netloc != '':
                next_page = url_for('employee.clock', employee_id=employee.id)
            return redirect(next_page)
        else:
            error = "Invalid credentials. Please try again."

    return render_template('login.html', error=error, message=message)

@auth_bp.route('/reset_request', methods=['GET', 'POST'])
@limiter.limit("5 per minute", key_func=custom_login_key)
def reset_request():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        user = Employee.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            return render_template('email_sent.html')
        else:
            error = "No user found with this email address."
    return render_template('reset_request.html', error=error)

@auth_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute", key_func=custom_login_key)
def reset_token(token):
    user = Employee.verify_reset_token(token)
    if not user:
        return render_template('link_expired.html')

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            error = "Passwords do not match. Please try again."
            return render_template('reset_token.html', error=error)

        if not is_strong_password(password):
            error = "Password is not strong enough. It must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a number."
            return render_template('reset_token.html', error=error)

        user.set_password(password)
        db.session.commit()
        return redirect(url_for('auth.login', message='Password successfully reset.'))

    return render_template('reset_token.html')

@auth_bp.route('/set_details/<token>', methods=['GET', 'POST'])
def set_details(token):
    user = Employee.verify_reset_token(token)
    if not user:
        return render_template('link_expired.html')

    error = None
    success = None

    if request.method == 'POST':
        name = request.form['name']
        surname = request.form['surname']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Profile picture processing (optional)
        file = request.files.get('profile_picture')
        if file and file.filename and allowed_file(file.filename):
            from flask import current_app
            import os

            # Ensure profile_pictures directory exists
            profile_pics_dir = os.path.join(current_app.root_path, 'static', 'profile_pictures')
            os.makedirs(profile_pics_dir, exist_ok=True)

            filename = f"{user.id}_{secrets.token_hex(8)}.{file.filename.rsplit('.', 1)[1].lower()}"
            relative_path = os.path.join('profile_pictures', filename).replace("\\", "/")
            filepath = os.path.join(current_app.root_path, 'static', 'profile_pictures', filename)
            file.save(filepath)
            user.profile_picture = relative_path

        # Password validation
        if password != confirm_password:
            error = "Passwords do not match. Please try again."
        elif not is_strong_password(password):
            error = "Password is not strong enough. It must be at least 8 characters long, contain an uppercase letter, a lowercase letter, and a number."
        else:
            user.name = name
            user.surname = surname
            user.set_password(password)
            user.is_authenticated = True
            db.session.commit()
            return redirect(url_for('auth.login', message='Details successfully set.'))

    return render_template('set_details.html', employee=user, error=error)

@auth_bp.route('/logout', methods=['POST'])
def logout():
    theme = request.cookies.get('theme', 'light')
    session.clear()
    response = make_response(redirect(url_for('auth.login')))
    response.set_cookie('theme', theme, max_age=60*60*24*30)
    return response

