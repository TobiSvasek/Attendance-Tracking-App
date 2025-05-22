from flask import Blueprint, request, redirect, render_template, url_for, jsonify, session
from app.models.employee import Employee
from app.models.attendance import Attendance
from app.models.status import Status
from app import db
from app.utils.helpers import is_valid_session, restrict_ip
from datetime import datetime, timedelta
import os

# Create a blueprint for main routes
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return redirect(url_for('auth.login'))


@main_bp.route('/main', methods=['GET', 'POST'])
@restrict_ip(os.getenv('ALLOWED_IPS', '').split(','))
def main_page():
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        return redirect(url_for('main.nfc_redirect', employee_id=employee_id))
    return render_template('main.html')


@main_bp.route('/nfc_redirect', methods=['POST'])
def nfc_redirect():
    employee_id = request.form.get('employee_id')
    employee = Employee.query.get(employee_id)
    if not employee:
        return redirect(url_for('main.main_page'))
    else:
        return redirect(url_for('main.employee_status', employee_id=employee_id))


@main_bp.route('/employee_status/<int:employee_id>', methods=['GET', 'POST'])
@restrict_ip(os.getenv('ALLOWED_IPS', '').split(','))
def employee_status(employee_id):
    employee = Employee.query.get(employee_id)
    if not employee or not employee.is_authenticated:
        return redirect(url_for('main.main_page'))

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

    return render_template('employee_status.html', employee=employee, success_message=success_message,
                          error_message=error_message, employees=employees, statuses=statuses)


@main_bp.route('/check_card', methods=['GET'])
def check_card():
    """Checks if an NFC card has been scanned and returns the redirect URL."""
    from app.utils.nfc import scanned_card_uid
    if scanned_card_uid:
        from app.utils.helpers import hash_uid
        uid = hash_uid(scanned_card_uid)  # Hash the UID
        scanned_card_uid = None  # Reset the UID after processing
        employee = Employee.query.filter_by(uid=uid).first()
        if employee:
            return jsonify({'redirect_url': url_for('main.employee_status', employee_id=employee.id)})
    return jsonify({'redirect_url': None})


@main_bp.route('/check_card_uid', methods=['GET'])
def check_card_uid():
    from app.utils.nfc import scanned_card_uid
    if scanned_card_uid:
        uid = scanned_card_uid
        scanned_card_uid = None  # Reset after reading
        return jsonify({'uid': uid})
    return jsonify({'uid': None})


@main_bp.route('/fetch_attendance/<int:employee_id>', methods=['GET'])
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


@main_bp.route('/fetch_attendance_day/<int:employee_id>', methods=['GET'])
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


@main_bp.route('/toggle_theme', methods=['POST'])
def toggle_theme():
    from flask import make_response
    from app import limiter
    from flask_limiter.errors import RateLimitExceeded

    if request.method == 'POST':
        try:
            # Only apply rate limiting here:
            limiter.limit("5 per minute")(lambda: None)()
        except RateLimitExceeded as e:
            return render_template("429.html", retry_after=int(
                e.description.split(' ')[-1]) if "Retry-After" in e.description else 60), 429

    current_theme = request.cookies.get('theme', 'light')
    new_theme = 'dark' if current_theme == 'light' else 'light'
    response = make_response(redirect(request.referrer))
    response.set_cookie('theme', new_theme, max_age=60*60*24*30)  # Cookie expires in 30 days
    return response

