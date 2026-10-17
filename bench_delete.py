import time
import os
from app import app, db, Employee, Status

def setup_db():
    with app.app_context():
        db.create_all()
        admin = Employee(email='admin@admin.com', password_hash='password', is_admin=True)
        db.session.add(admin)
        db.session.commit()
        return admin.id

def create_employees(n):
    with app.app_context():
        employees = []
        for i in range(n):
            emp = Employee(email=f'user_{time.time()}_{i}@test.com', password_hash='password', is_admin=False)
            employees.append(emp)
        db.session.add_all(employees)
        db.session.commit()
        return [emp.id for emp in employees]

def benchmark_current(ids):
    with app.app_context():
        start = time.time()

        employees_to_delete = Employee.query.filter(Employee.id.in_(ids)).all()
        non_admin_employees = [emp for emp in employees_to_delete if not emp.is_admin]

        if non_admin_employees:
            for emp in non_admin_employees:
                db.session.delete(emp)
            db.session.commit()

        end = time.time()
        return end - start

def benchmark_optimized(ids):
    with app.app_context():
        start = time.time()

        deleted_count = Employee.query.filter(
            Employee.id.in_(ids),
            Employee.is_admin == False
        ).delete(synchronize_session=False)
        db.session.commit()

        end = time.time()
        return end - start

if __name__ == '__main__':
    if os.path.exists('instance/database.db'):
        os.remove('instance/database.db')

    setup_db()

    # Measure current
    ids = create_employees(500)
    current_time = benchmark_current(ids)
    print(f"Current method time for 500 records: {current_time:.4f}s")

    # Measure optimized
    ids = create_employees(500)
    optimized_time = benchmark_optimized(ids)
    print(f"Optimized method time for 500 records: {optimized_time:.4f}s")
