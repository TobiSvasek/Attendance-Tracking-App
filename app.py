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
from flask import current_app, url_for, render_template
from flask_mail import Message
import secrets
import string
from pyngrok import ngrok, conf
from smartcard.System import readers
from smartcard.Exceptions import NoCardException
from smartcard.util import toHexString
from flask import jsonify
import threading
from datetime import datetime, timedelta
import hashlib
from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded
from flask_limiter.util import get_remote_address
from redis import Redis
from flask_socketio import SocketIO, emit

app = Flask(__name__, template_folder='templates')
socketio = SocketIO(app, cors_allowed_origins="*")

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
    name = db.Column(db.String(100), nullable=True)
    surname = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    uid = db.Column(db.String(50), unique=True, nullable=True)
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_authenticated = db.Column(db.Boolean, default=False)
    session_token = db.Column(db.String(64), nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True, default='profile_pictures/default.png')

    status = db.relationship('Status', backref='employees')
    attendances = db.relationship('Attendance', backref='employee', lazy=True, cascade="all, delete-orphan")

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

def go_back():
    return "<script>window.history.back();</script>", 200

def generate_session_token():
    return secrets.token_hex(32)

def is_valid_session():
    employee_id = session.get('employee_id')
    session_token = session.get('session_token')

    if not employee_id or not session_token:
        return False

    employee = Employee.query.get(employee_id)
    if not employee or employee.session_token != session_token:
        return False

    return True

def restrict_ip(allowed_ips):
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

redis_client = Redis(host='localhost', port=6379, db=0)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="redis://localhost:6379/0",
    default_limits=[]
)

def custom_login_key():
    if request.method == 'POST':
        return f"{get_remote_address()}:{request.form.get('email', '')}"
    return get_remote_address()

@app.context_processor
def inject_logged_in_employee():
    if 'employee_id' in session:
        employee = Employee.query.get(session['employee_id'])
        return dict(logged_in_employee=employee)
    return dict(logged_in_employee=None)

@socketio.on('connect')
def handle_connect():
    print("Reader initialized.")

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/main', methods=['GET', 'POST'])
@restrict_ip(os.getenv('ALLOWED_IPS', '').split(','))
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
@restrict_ip(os.getenv('ALLOWED_IPS', '').split(','))
def employee_status(employee_id):
    employee = Employee.query.get(employee_id)
    if not employee or not employee.is_authenticated:
        return redirect(url_for('main_page'))

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
    if not is_valid_session():
        session.clear()
        return redirect(url_for('login'))

    logged_in_employee_id = session['employee_id']
    logged_in_employee = Employee.query.get(logged_in_employee_id)

    if logged_in_employee_id != employee_id:
        return go_back()

    employee = Employee.query.get(employee_id)
    if not employee:
        return go_back()

    success_message = None
    error_message = None

    if request.method == 'POST':
        status_id = request.form.get('status_id')
        if status_id:
            if employee.status_id == int(status_id):
                error_message = "You are already in this status."
            else:
                new_status = Status.query.get(status_id)
                if new_status:
                    employee.status_id = status_id
                    new_attendance = Attendance(employee_id=employee.id, status_id=status_id, update_time=datetime.now())
                    db.session.add(new_attendance)
                    db.session.commit()
                    success_message = "Status updated successfully!"

    statuses = Status.query.all()
    employees = Employee.query.all() if logged_in_employee.is_admin else None
    attendances = Attendance.query.filter_by(employee_id=employee_id).order_by(Attendance.update_time.desc()).all()

    return render_template('clock.html', employee=employee, success_message=success_message, error_message=error_message, employees=employees, statuses=statuses, attendances=attendances,logged_in_employee=logged_in_employee ,show_profile_picture=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    message = request.args.get('message')

    if request.method == 'POST':
        try:
            # Only apply rate limiting here:
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
                next_page = url_for('clock', employee_id=employee.id)
            return redirect(next_page)
        else:
            error = "Invalid credentials. Please try again."

    return render_template('login.html', error=error, message=message)

@app.route('/reset_request', methods=['GET', 'POST'])
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

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
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
        return redirect(url_for('login', message='Password successfully reset.'))
    return render_template('reset_token.html')

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

def send_set_details_email(user):
    token = user.generate_reset_token()
    set_details_url = url_for('set_details', token=token, _external=True)

    html = render_template('email_templates/set_password_email.html', set_details=set_details_url)

    msg = Message('Set Your Account Details',
                  recipients=[user.email])
    msg.body = f'''A user account has been created for you. To set your name, surname, and password, visit the following link:
{set_details_url}

If you did not expect this email, please ignore it.
'''
    msg.html = html

    with current_app.open_resource('static/logo.png') as fp:
        msg.attach('logo.png', 'image/png', fp.read(), 'inline', headers={'Content-ID': '<logo_cid>'})

    mail.send(msg)


@app.route('/clock_history/<int:employee_id>')
def view_clock_history(employee_id):
    if not is_valid_session():
        session.clear()
        return redirect(url_for('login'))

    logged_in_employee_id = session['employee_id']
    logged_in_employee = Employee.query.get(logged_in_employee_id)

    if not logged_in_employee.is_admin:
        return go_back()

    employee = Employee.query.get(employee_id)
    if not employee:
        return go_back()

    attendances = Attendance.query.filter_by(employee_id=employee_id).order_by(Attendance.update_time.desc()).all()
    return render_template('clock_history.html', employee=employee, attendances=attendances, is_admin=logged_in_employee.is_admin, admin_id=logged_in_employee_id, logged_in_employee=logged_in_employee,show_profile_picture=True)

def generate_random_password(length=12):
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

FIRST_NAME = "NEW"
SURNAME = "USER"
@app.route('/add_employee', methods=['GET', 'POST'])
def add_employee():
    error = None
    success_message = None

    if 'employee_id' not in session:
        return redirect(url_for('login'))

    logged_in_employee = Employee.query.get(session['employee_id'])
    if not logged_in_employee.is_admin:
        return go_back()

    if request.method == 'POST':
        email = request.form['email']
        uid_raw = request.form.get('uid')
        is_admin = 'is_admin' in request.form

        if not uid_raw:
            error = "No NFC card scanned. Please scan the card first."
        else:
            hashed_uid = hashlib.sha256(uid_raw.encode()).hexdigest()

            if Employee.query.filter_by(email=email).first():
                error = "An employee with this email already exists."
            elif Employee.query.filter_by(uid=hashed_uid).first():
                error = "This NFC card is already assigned to another employee."
            else:
                new_employee = Employee(
                    email=email,
                    uid=hashed_uid,
                    is_admin=is_admin,
                    name="NEW",
                    surname="USER",
                    profile_picture='profile_pictures/default.png'
                )
                new_employee.set_password(generate_random_password())
                db.session.add(new_employee)
                db.session.commit()

                send_set_details_email(new_employee)
                success_message = "Employee added successfully!"

    return render_template('add_employee.html', error=error, success_message=success_message,logged_in_employee=logged_in_employee ,show_profile_picture=True)

@app.route('/set_details/<token>', methods=['GET', 'POST'])
def set_details(token):
    user = Employee.verify_reset_token(token)
    if not user:
        return render_template('link_expired.html')

    if request.method == 'POST':
        name = request.form['name']
        surname = request.form['surname']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            error = "Passwords do not match. Please try again."
            return render_template('set_details.html', error=error, employee=user)

        if not is_strong_password(password):
            error = "Password is not strong enough. It must be at least 8 characters long, contain an uppercase letter, a lowercase letter, and a number."
            return render_template('set_details.html', error=error, employee=user)

        user.name = name
        user.surname = surname
        user.set_password(password)
        user.is_authenticated = True  # Set is_authenticated to True
        db.session.commit()
        return redirect(url_for('login', message='Details successfully set.'))

    return render_template('set_details.html', employee=user)


@app.route('/upload_profile_picture/<int:employee_id>', methods=['POST'])
def upload_profile_picture(employee_id):
    if 'profile_picture' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['profile_picture']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        # Generate a unique filename
        filename = f"{employee_id}_{secrets.token_hex(8)}.{file.filename.rsplit('.', 1)[1].lower()}"
        relative_path = os.path.join('profile_pictures', filename).replace("\\", "/")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        try:
            # Save the file to the static directory
            file.save(filepath)

            # Update the employee's profile_picture field with the relative path
            employee = Employee.query.get(employee_id)
            if employee:
                employee.profile_picture = relative_path  # Store relative path
                db.session.commit()
                return '', 204
            else:
                return jsonify({'error': 'Employee not found'}), 404
        except Exception as e:
            return jsonify({'error': f'File upload failed: {str(e)}'}), 500

    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/delete_employee', methods=['GET', 'POST'])
def delete_employee():
    if 'employee_id' not in session:
        return go_back()

    logged_in_employee_id = session['employee_id']
    logged_in_employee = Employee.query.get(logged_in_employee_id)

    if not logged_in_employee.is_admin:
        return go_back()

    error = None
    if request.method == 'POST':
        employee_ids = request.form.get('employee_ids')
        if employee_ids:
            ids_to_delete = [int(emp_id) for emp_id in employee_ids.split(',') if emp_id.isdigit()]
            employees_to_delete = Employee.query.filter(Employee.id.in_(ids_to_delete)).all()

            non_admin_employees = [emp for emp in employees_to_delete if not emp.is_admin]

            if not non_admin_employees:
                error = "No valid employees selected for deletion."
            else:
                for emp in non_admin_employees:
                    db.session.delete(emp)
                db.session.commit()
        else:
            error = "No employees selected for deletion."

    # Fetch only non-admin employees
    employees = Employee.query.filter_by(is_admin=False).all()
    return render_template('delete_employee.html', employees=employees, error=error,logged_in_employee=logged_in_employee ,show_profile_picture=True)

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
    response.set_cookie('theme', theme, max_age=60*60*24*30)
    return response

# Global variable to store the scanned card UID
scanned_card_uid = None

def nfc_card_scanner():
    """Continuously scans for NFC cards and emits event via WebSocket."""
    r = readers()
    if not r:
        print("No NFC reader detected.")
        return

    reader = r[0]
    connection = reader.createConnection()
    last_uid = None

    while True:
        try:
            connection.connect()
            GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
            response, sw1, sw2 = connection.transmit(GET_UID)

            if sw1 == 0x90 and sw2 == 0x00:
                uid = toHexString(response)

                if uid != last_uid:
                    last_uid = uid
                    print(f"Card detected: {uid}")

                    hashed_uid = hashlib.sha256(uid.encode()).hexdigest()

                    with app.app_context():
                        employee = Employee.query.filter_by(uid=hashed_uid).first()

                        if employee:
                            print(f"Card belongs to employee_id={employee.id}")
                            socketio.emit('card_scanned', {'employee_id': employee.id})
                        else:
                            print("Card not assigned, emitting raw UID")
                            socketio.emit('card_scanned', {'uid': uid})

            else:
                last_uid = None

        except NoCardException:
            last_uid = None
        except Exception as e:
            print(f"[NFC ERROR] {e}")


threading.Thread(target=nfc_card_scanner, daemon=True).start()

@app.route('/check_card', methods=['GET'])
def check_card():
    """Checks if an NFC card has been scanned and returns the redirect URL."""
    global scanned_card_uid
    if scanned_card_uid:
        uid = hashlib.sha256(scanned_card_uid.encode()).hexdigest()  # Hash the UID
        scanned_card_uid = None  # Reset the UID after processing
        employee = Employee.query.filter_by(uid=uid).first()
        if employee:
            return jsonify({'redirect_url': url_for('employee_status', employee_id=employee.id)})
    return jsonify({'redirect_url': None})

@app.route('/check_card_uid', methods=['GET'])
def check_card_uid():
    global scanned_card_uid
    if scanned_card_uid:
        uid = scanned_card_uid
        scanned_card_uid = None  # Reset after reading
        return jsonify({'uid': uid})
    return jsonify({'uid': None})

@app.route('/fetch_attendance/<int:employee_id>', methods=['GET'])
def fetch_attendance(employee_id):
    if not is_valid_session():
        return jsonify({'error': 'Invalid session'}), 403

    logged_in_id = session['employee_id']
    logged_in_employee = Employee.query.get(logged_in_id)
    if logged_in_id != employee_id and not logged_in_employee.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    month = int(request.args.get('month'))
    year = int(request.args.get('year'))
    start_date = datetime(year, month, 1)
    end_date = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)

    attendance = Attendance.query.filter(
        Attendance.employee_id == employee_id,
        Attendance.update_time >= start_date,
        Attendance.update_time < end_date
    ).all()

    attendance_dates = [a.update_time.strftime('%Y-%m-%d') for a in attendance]
    return jsonify({'attendance': list(set(attendance_dates))})

@app.route('/fetch_attendance_day/<int:employee_id>', methods=['GET'])
def fetch_attendance_day(employee_id):
    if not is_valid_session():
        return jsonify({'error': 'Invalid session'}), 403

    logged_in_id = session['employee_id']
    logged_in_employee = Employee.query.get(logged_in_id)
    if logged_in_id != employee_id and not logged_in_employee.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    date = request.args.get('date')
    start_date = datetime.strptime(date, '%Y-%m-%d')
    end_date = start_date + timedelta(days=1)

    attendance = Attendance.query.filter(
        Attendance.employee_id == employee_id,
        Attendance.update_time >= start_date,
        Attendance.update_time < end_date
    ).all()

    attendance_records = [
        {'time': a.update_time.strftime('%H:%M:%S'), 'status': a.status.name} for a in attendance
    ]

    return jsonify({'attendance': attendance_records})

@app.errorhandler(429)
def ratelimit_handler(e):
    retry_after = int(e.description.split(' ')[-1]) if "Retry-After" in e.description else 60
    return render_template("429.html", retry_after=retry_after), 429


# Set the path to your ngrok configuration file
conf.get_default().config_path = os.getenv('CONFIG_PATH')
conf.get_default().auth_token = os.getenv('NGROK_AUTH_TOKEN')

app.config['UPLOAD_FOLDER'] = 'static/profile_pictures'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Limit file size to 2MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Start ngrok tunnel
    public_url = ngrok.connect(5000)
    print(" * ngrok tunnel \"{}\" -> \"http://127.0.0.1:5000\"".format(public_url))
    socketio.run(app, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)