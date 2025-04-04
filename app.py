from flask import Flask, request, redirect, session, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlsplit
from flask_migrate import Migrate
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer
import re
from dotenv import load_dotenv
import os
app = Flask(__name__, template_folder='templates')

load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    surname = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_authenticated = db.Column(db.Boolean, default=False)

    status = db.relationship('Status', backref='employees')
    attendances = db.relationship('Attendance', backref='employee', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps(self.email, salt='password-reset-salt')

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            email = s.loads(token, salt='password-reset-salt', max_age=expires_sec)
        except:
            return None
        return Employee.query.filter_by(email=email).first()

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=False)
    update_time = db.Column(db.DateTime, nullable=False, default=datetime.now)

    status = db.relationship('Status', backref='attendances')

class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/main', methods=['GET', 'POST'])
def main_page():
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        return redirect(url_for('nfc_redirect', employee_id=employee_id))
    return render_template('main.html')

@app.route('/nfc_redirect', methods=['POST'])
def nfc_redirect():
    employee_id = request.form.get('employee_id')
    employee = Employee.query.get(employee_id)
    if not employee:
        return redirect(url_for('main_page'))
    else:
        return redirect(url_for('employee_status', employee_id=employee_id))


@app.route('/employee_status/<int:employee_id>', methods=['GET', 'POST'])
def employee_status(employee_id):
    employee = Employee.query.get(employee_id)
    if not employee or not employee.is_authenticated:
        return redirect(url_for('login'))

    success_message = None
    error_message = None

    if request.method == 'POST':
        status_id = request.form.get('status_id')
        if status_id:
            if employee.status_id == int(status_id):
                success_message = "You are already in this status."
            else:
                employee.status_id = status_id
                new_attendance = Attendance(employee_id=employee.id, status_id=status_id, update_time=datetime.now())
                db.session.add(new_attendance)
                db.session.commit()
                success_message = "Status updated successfully!"

    statuses = Status.query.all()
    employees = Employee.query.all() if employee.is_admin else None

    return render_template('employee_status.html', employee=employee, success_message=success_message, error_message=error_message, employees=employees, statuses=statuses)

@app.route('/clock/<int:employee_id>', methods=['GET', 'POST'])
def clock(employee_id):
    employee = Employee.query.get(employee_id)
    if not employee or not employee.is_authenticated:
        return redirect(url_for('login'))

    success_message = None
    error_message = None

    if request.method == 'POST':
        status_id = request.form.get('status_id')
        if status_id:
            if employee.status_id == int(status_id):
                success_message = "You are already in this status."
            else:
                employee.status_id = status_id
                new_attendance = Attendance(employee_id=employee.id, status_id=status_id, update_time=datetime.now())
                db.session.add(new_attendance)
                db.session.commit()
                success_message = "Status updated successfully!"

    statuses = Status.query.all()
    employees = Employee.query.all() if employee.is_admin else None
    attendances = Attendance.query.filter_by(employee_id=employee_id).order_by(Attendance.update_time.desc()).all()

    return render_template('clock.html', employee=employee, success_message=success_message, error_message=error_message, employees=employees, statuses=statuses, attendances=attendances)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    message = request.args.get('message')
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        employee = Employee.query.filter_by(email=email).first()

        if employee and employee.check_password(password):
            session['employee_id'] = employee.id
            session['login_time'] = datetime.now().timestamp()
            employee.is_authenticated = True
            db.session.commit()
            next_page = request.args.get('next')
            if not next_page or urlsplit(next_page).netloc != '':
                next_page = url_for('clock', employee_id=employee.id)
            return redirect(next_page)
        else:
            error = "Invalid credentials. Please try again."

    return render_template('login.html', error=error, message=message)

@app.route('/reset_request', methods=['GET', 'POST'])
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

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = Employee.verify_reset_token(token)
    if not user:
        return render_template('link_expired.html')
    if request.method == 'POST':
        password = request.form['password']
        if not is_strong_password(password):
            error = "Password is not strong enough. It must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a number."
            return render_template('reset_token.html', error=error)
        user.set_password(password)
        db.session.commit()
        return redirect(url_for('login', message='Password successfully reset.'))
    return render_template('reset_token.html')


import base64
from flask import current_app, url_for, render_template
from flask_mail import Message

def send_reset_email(user):
    token = user.generate_reset_token()
    reset_url = url_for('reset_token', token=token, _external=True)

    html = render_template('email_templates/reset_password_email.html', reset_url=reset_url)

    msg = Message('Password Reset Request',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.
'''
    msg.html = html

    with current_app.open_resource('static/logo.png') as fp:
        msg.attach('logo.png', 'image/png', fp.read(), 'inline', headers={'Content-ID': '<logo_cid>'})

    mail.send(msg)

def send_set_password_email(user):
    token = user.generate_reset_token()
    set_password_url = url_for('reset_token', token=token, _external=True)

    # Read the logo image and encode it in base64
    with current_app.open_resource('static/logo.png', 'rb') as image_file:
        logo_base64 = base64.b64encode(image_file.read()).decode('utf-8')

    html = render_template('email_templates/set_password_email.html', set_password_url=set_password_url, logo_base64=logo_base64)

    msg = Message('Set Your Password',
                  recipients=[user.email])
    msg.body = f'''A user account has been created for you. To set your password, visit the following link:
{set_password_url}

If you did not expect this email, please ignore it.
'''
    msg.html = html
    mail.send(msg)

@app.route('/clock_history/<int:employee_id>')
def view_clock_history(employee_id):
    if 'employee_id' not in session:
        return redirect(url_for('login'))

    admin_id = session['employee_id']
    employee = Employee.query.get(employee_id)
    if not employee:
        return redirect(url_for('clock', employee_id=admin_id))

    attendances = Attendance.query.filter_by(employee_id=employee_id).order_by(Attendance.update_time.desc()).all()
    is_admin = Employee.query.get(admin_id).is_admin
    return render_template('clock_history.html', employee=employee, attendances=attendances, is_admin=is_admin, admin_id=admin_id)

import secrets
import string

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for i in range(length))

from flask import flash

@app.route('/add_employee', methods=['GET', 'POST'])
def add_employee():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        surname = request.form['surname']
        isAdmin = 'is_admin' in request.form  # Convert to boolean

        # Check if the user already exists
        existing_employee = Employee.query.filter_by(email=email).first()
        if existing_employee:
            error = f"User with email {email} already exists."
            return render_template('add_employee.html', error=error)

        default_password = generate_random_password()  # Generate a random password

        new_employee = Employee(email=email, name=name, surname=surname, is_admin=isAdmin)
        new_employee.set_password(default_password)  # Set the random password
        db.session.add(new_employee)
        db.session.commit()

        send_set_password_email(new_employee)

        flash(f'User {name} {surname} created and email sent to {email}.', 'success')
        return redirect(url_for('clock'))

    return render_template('add_employee.html', error=error)

@app.route('/delete_employee', methods=['GET', 'POST'])
def delete_employee():
    if 'employee_id' not in session:
        return redirect(url_for('login'))

    employee = Employee.query.get(session['employee_id'])
    if not employee.is_admin:
        return redirect(url_for('clock'))

    error = None
    if request.method == 'POST':
        employee_ids = request.form.get('employee_ids')
        if employee_ids:
            employee_ids = employee_ids.split(',')
            for emp_id in employee_ids:
                employee_to_delete = Employee.query.get(emp_id)
                if employee_to_delete:
                    # Delete associated attendance records
                    Attendance.query.filter_by(employee_id=emp_id).delete()
                    db.session.delete(employee_to_delete)
            db.session.commit()
            return redirect(url_for('clock'))
        else:
            error = "No employees selected for deletion."

    employees = Employee.query.filter_by(is_admin=False).all()
    return render_template('delete_employee.html', employees=employees, error=error)

@app.route('/toggle_theme', methods=['POST'])
def toggle_theme():
    current_theme = request.cookies.get('theme', 'light')
    new_theme = 'dark' if current_theme == 'light' else 'light'
    response = make_response(redirect(request.referrer))
    response.set_cookie('theme', new_theme, max_age=60*60*24*30)  # Cookie expires in 30 days
    return response

@app.route('/logout', methods=['POST'])
def logout():
    theme = request.cookies.get('theme', 'light')
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.set_cookie('theme', theme, max_age=60*60*24*30)  # Retain the theme cookie
    return response

from pyngrok import ngrok, conf

# Set the path to your ngrok configuration file
conf.get_default().config_path = r"C:\Users\HP\AppData\Local\ngrok\ngrok.yml"
conf.get_default().auth_token = os.getenv('NGROK_AUTH_TOKEN')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Start ngrok tunnel
    public_url = ngrok.connect(5000)
    print(" * ngrok tunnel \"{}\" -> \"http://127.0.0.1:5000\"".format(public_url))
    app.run(debug=True, use_reloader=False)
