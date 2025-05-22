from flask import Blueprint, render_template, request, redirect, url_for, session
from app.models.employee import Employee
from app import db
from app.utils.helpers import go_back, generate_random_password, hash_uid
from app.utils.email import send_set_details_email
import secrets
import os
import hashlib

# Create a blueprint for admin routes
admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/add_employee', methods=['GET', 'POST'])
def add_employee():
    error = None
    success_message = None

    if 'employee_id' not in session:
        return redirect(url_for('auth.login'))

    logged_in_employee = Employee.query.get(session['employee_id'])
    if not logged_in_employee or not logged_in_employee.is_admin:
        return go_back()

    if request.method == 'POST':
        email = request.form['email']
        uid_raw = request.form.get('uid')
        is_admin = 'is_admin' in request.form

        if not uid_raw:
            error = "No NFC card scanned. Please scan the card first."
        else:
            hashed_uid = hash_uid(uid_raw)

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

    return render_template('add_employee.html', error=error, success_message=success_message,
                          logged_in_employee=logged_in_employee, show_profile_picture=True)


@admin_bp.route('/delete_employee', methods=['GET', 'POST'])
def delete_employee():
    if 'employee_id' not in session:
        return go_back()

    logged_in_employee_id = session['employee_id']
    logged_in_employee = Employee.query.get(logged_in_employee_id)

    if not logged_in_employee or not logged_in_employee.is_admin:
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
    return render_template('delete_employee.html', employees=employees, error=error,
                          logged_in_employee=logged_in_employee, show_profile_picture=True)

