from flask import Blueprint, render_template, request, redirect, url_for, session
from app.models.employee import Employee
from app.models.attendance import Attendance
from app.models.status import Status
from app import db
from app.utils.helpers import is_valid_session, go_back, allowed_file
from datetime import datetime
import os
import secrets

# Create a blueprint for employee routes
employee_bp = Blueprint('employee', __name__)

@employee_bp.route('/clock/<int:employee_id>', methods=['GET', 'POST'])
def clock(employee_id):
    if not is_valid_session():
        session.clear()
        return redirect(url_for('auth.login'))

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

    return render_template('clock.html', employee=employee, success_message=success_message, error_message=error_message,
                          employees=employees, statuses=statuses, attendances=attendances,
                          logged_in_employee=logged_in_employee, show_profile_picture=True)


@employee_bp.route('/clock_history/<int:employee_id>')
def view_clock_history(employee_id):
    if not is_valid_session():
        session.clear()
        return redirect(url_for('auth.login'))

    logged_in_employee_id = session['employee_id']
    logged_in_employee = Employee.query.get(logged_in_employee_id)

    # User can view their own history, admin can view anyone's
    if logged_in_employee_id != employee_id and not logged_in_employee.is_admin:
        return go_back()

    employee = Employee.query.get(employee_id)
    if not employee:
        return go_back()

    attendances = Attendance.query.filter_by(employee_id=employee_id).order_by(Attendance.update_time.desc()).all()
    return render_template('clock_history.html', employee=employee, attendances=attendances,
                          is_admin=logged_in_employee.is_admin, admin_id=logged_in_employee_id,
                          logged_in_employee=logged_in_employee, show_profile_picture=True)


@employee_bp.route('/edit_employee/<int:employee_id>', methods=['GET', 'POST'])
def edit_employee(employee_id):
    if 'employee_id' not in session:
        return redirect(url_for('auth.login'))

    logged_in_employee = Employee.query.get(session['employee_id'])
    if not logged_in_employee:
        return go_back()

    # Users can edit themselves, admin can edit anyone
    if not logged_in_employee.is_admin and logged_in_employee.id != employee_id:
        return go_back()

    employee = Employee.query.get(employee_id)
    if not employee:
        return go_back()

    success = request.args.get('success')
    error = request.args.get('error')
    success_upload = request.args.get('success_upload')

    if request.method == 'POST':
        employee.name = request.form.get('name')
        employee.surname = request.form.get('surname')

        # Only admin can change admin status
        if logged_in_employee.is_admin:
            employee.is_admin = 'is_admin' in request.form

        db.session.commit()
        success = "User updated successfully."

    return render_template(
        'edit_employee.html',
        employee=employee,
        error=error,
        success=success,
        logged_in_employee=logged_in_employee,
        show_profile_picture=True,
        success_upload=success_upload
    )


@employee_bp.route('/upload_profile_picture/<int:employee_id>', methods=['POST'])
def upload_profile_picture(employee_id):
    from flask import current_app

    if 'employee_id' not in session:
        return redirect(url_for('auth.login'))

    logged_in_employee = Employee.query.get(session['employee_id'])
    # Users can upload their own profile picture, admin can upload for anyone
    if not logged_in_employee.is_admin and logged_in_employee.id != employee_id:
        return go_back()

    if 'profile_picture' not in request.files:
        return redirect(url_for('employee.edit_employee', employee_id=employee_id, error='No file selected'))

    file = request.files['profile_picture']
    if file.filename == '':
        return redirect(url_for('employee.edit_employee', employee_id=employee_id, error='No file selected'))

    if file and allowed_file(file.filename):
        # Ensure profile_pictures directory exists
        profile_pics_dir = os.path.join(current_app.root_path, 'static', 'profile_pictures')
        os.makedirs(profile_pics_dir, exist_ok=True)

        filename = f"{employee_id}_{secrets.token_hex(8)}.{file.filename.rsplit('.', 1)[1].lower()}"
        relative_path = os.path.join('profile_pictures', filename).replace("\\", "/")
        filepath = os.path.join(current_app.root_path, 'static', 'profile_pictures', filename)

        try:
            file.save(filepath)
            employee = Employee.query.get(employee_id)
            if employee:
                employee.profile_picture = relative_path
                db.session.commit()
                return redirect(url_for('employee.edit_employee', employee_id=employee.id, success_upload='1'))
            else:
                return redirect(url_for('employee.edit_employee', employee_id=employee_id, error='Employee not found'))
        except Exception as e:
            return redirect(url_for('employee.edit_employee', employee_id=employee_id, error=f'Upload failed: {str(e)}'))

    return redirect(url_for('employee.edit_employee', employee_id=employee_id, error='Invalid file type'))

