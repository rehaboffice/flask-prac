# routes.py
from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db
from models import User, EmployeeProfile, Department, LeaveRequest, Attendance, Salary, LeaveBalance
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

routes = Blueprint('routes', __name__)

# ---------- ROLE-BASED DECORATORS ----------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    # return decorated_function

def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'manager':
            return jsonify({"error": "Manager access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# ---------- AUTH ROUTES ----------
@routes.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        return jsonify({"message": "Login successful"})
    return jsonify({"error": "Invalid credentials"}), 401

@routes.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"})

# ---------- ADMIN ROUTES ----------
@routes.route('/admin/profile/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user_profile(user_id):
    profile = EmployeeProfile.query.filter_by(user_id=user_id).first()
    if profile:
        data = request.json
        profile.name = data.get('name', profile.name)
        profile.contact_email = data.get('contact_email', profile.contact_email)
        profile.phone_number = data.get('phone_number', profile.phone_number)
        db.session.commit()
        return jsonify({"message": "Profile updated successfully"})
    return jsonify({"error": "Profile not found"}), 404

@routes.route('/admin/profile', methods=['PUT'])
@login_required
@admin_required
def update_admin_profile():
    profile = EmployeeProfile.query.filter_by(user_id=current_user.id).first()
    if profile:
        data = request.json
        profile.name = data.get('name', profile.name)
        profile.contact_email = data.get('contact_email', profile.contact_email)
        profile.phone_number = data.get('phone_number', profile.phone_number)
        db.session.commit()
        return jsonify({"message": "Admin profile updated successfully"})
    return jsonify({"error": "Profile not found"}), 404

@routes.route('/admin/add_user', methods=['POST'])
@login_required
@admin_required
def add_user():
    data = request.json
    hashed_password = generate_password_hash(data['password'])
    new_user = User(email=data['email'], password=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully", "user_id": new_user.id})

@routes.route('/admin/add_manager', methods=['POST'])
@login_required
@admin_required
def add_manager():
    data = request.json
    hashed_password = generate_password_hash(data['password'])
    new_user = User(email=data['email'], password=hashed_password, role='manager')
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Manager created successfully", "user_id": new_user.id})



@routes.route('/admin/add_employee_profile', methods=['POST'])
@login_required
@admin_required
def add_employee_profile():
    data = request.json
    new_profile = EmployeeProfile(
        user_id=data['user_id'],
        name=data['name'],
        contact_email=data['contact_email'],
        phone_number=data.get('phone_number'),
        department_id=data.get('department_id'),
        manager_id=data.get('manager_id')
    )
    db.session.add(new_profile)
    db.session.commit()
    db.session.add(LeaveBalance(user_id=data['user_id']))
    db.session.commit()
    return jsonify({"message": "Employee profile created"})

@routes.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted"})
    return jsonify({"error": "User not found"}), 404

@routes.route('/admin/change_salary/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def change_salary(user_id):
    data = request.json
    salary = Salary.query.filter_by(user_id=user_id).first()
    if not salary:
        salary = Salary(user_id=user_id, amount=data['amount'])
        db.session.add(salary)
    else:
        salary.amount = data['amount']
    db.session.commit()
    return jsonify({"message": "Salary updated"})

@routes.route('/admin/view_all_leaves')
@login_required
@admin_required
def view_all_leaves():
    leaves = LeaveRequest.query.all()
    return jsonify([{
        'id': l.id,
        'user_id': l.user_id,
        'status': l.status,
        'start_date': str(l.start_date),
        'end_date': str(l.end_date),
        'reason': l.reason
    } for l in leaves])

@routes.route('/admin/approve_leave/<int:leave_id>', methods=['POST'])
@login_required
@admin_required
def admin_approve_leave(leave_id):
    leave = LeaveRequest.query.get(leave_id)
    if not leave:
        return jsonify({"error": "Leave not found"}), 404
    if leave.manager_status != 'approved':
        return jsonify({"error": "Manager has not approved this leave"}), 403
    leave.admin_status = 'approved'
    db.session.commit()
    return jsonify({"message": "Leave approved by admin"})

@routes.route('/admin/view_attendance')
@login_required
@admin_required
def view_attendance():
    records = Attendance.query.all()
    summary = {}
    for r in records:
        if r.user_id not in summary:
            summary[r.user_id] = []
        summary[r.user_id].append(str(r.timestamp))
    return jsonify(summary)

@routes.route('/admin/departments', methods=['POST', 'DELETE'])
@login_required
@admin_required
def manage_departments():
    data = request.json
    if request.method == 'POST':
        dept = Department(name=data['name'])
        db.session.add(dept)
        db.session.commit()
        return jsonify({"message": "Department added"})
    else:
        dept = Department.query.filter_by(name=data['name']).first()
        if dept:
            db.session.delete(dept)
            db.session.commit()
            return jsonify({"message": "Department deleted"})
        return jsonify({"error": "Department not found"}), 404

@routes.route('/admin/employees')
@login_required
@admin_required
def get_all_employees():
    profiles = EmployeeProfile.query.all()
    return jsonify([{
        'user_id': p.user_id,
        'name': p.name,
        'email': p.contact_email
    } for p in profiles])

@routes.route('/admin/leave_balances')
@login_required
@admin_required
def get_leave_balances():
    balances = LeaveBalance.query.all()
    return jsonify([{ "user_id": b.user_id, "remaining_leaves": b.remaining_leaves } for b in balances])

@routes.route('/admin/departments', methods=['GET'])
@login_required
@admin_required
def get_departments():
    departments = Department.query.all()
    return jsonify([{ "id": d.id, "name": d.name } for d in departments])

@routes.route('/admin/managers', methods=['GET'])
@login_required
@admin_required
def get_all_managers():
    managers = User.query.filter_by(role='manager').all()
    return jsonify([{ "id": m.id, "email": m.email } for m in managers])

@routes.route('/admin/assign_manager', methods=['POST'])
@login_required
@admin_required
def assign_manager():
    data = request.json
    profile = EmployeeProfile.query.filter_by(user_id=data['employee_id']).first()
    if not profile:
        return jsonify({"error": "Employee not found"}), 404
    profile.manager_id = data['manager_id']
    db.session.commit()
    return jsonify({"message": "Manager assigned to employee"})

@routes.route('/admin/assign_department', methods=['POST'])
@login_required
@admin_required
def assign_department():
    data = request.json
    profile = EmployeeProfile.query.filter_by(user_id=data['employee_id']).first()
    if not profile:
        return jsonify({"error": "Employee not found"}), 404
    profile.department_id = data['department_id']
    db.session.commit()
    return jsonify({"message": "Department assigned to employee"})

# ---------- MANAGER ROUTES ----------
@routes.route('/manager/profile', methods=['PUT'])
@login_required
@manager_required
def update_manager_profile():
    profile = EmployeeProfile.query.filter_by(user_id=current_user.id).first()
    if profile:
        data = request.json
        profile.name = data.get('name', profile.name)
        profile.contact_email = data.get('contact_email', profile.contact_email)
        profile.phone_number = data.get('phone_number', profile.phone_number)
        db.session.commit()
        return jsonify({"message": "Manager profile updated successfully"})
    return jsonify({"error": "Profile not found"}), 404

@routes.route('/manager/request_leave', methods=['POST'])
@login_required
@manager_required
def manager_request_leave():
    data = request.json
    new_leave = LeaveRequest(
        user_id=current_user.id,
        start_date=datetime.strptime(data['start_date'], '%Y-%m-%d'),
        end_date=datetime.strptime(data['end_date'], '%Y-%m-%d'),
        reason=data['reason'],
        manager_status='approved',  # Directly goes to admin
        admin_status='pending'
    )
    db.session.add(new_leave)
    db.session.commit()
    return jsonify({"message": "Leave request submitted to admin"})

@routes.route('/manager/leaves', methods=['GET'])
@login_required
@manager_required
def manager_view_all_leaves():
    leaves = LeaveRequest.query.all()
    return jsonify([
        {
            "id": l.id,
            "user_id": l.user_id,
            "start_date": l.start_date.strftime('%Y-%m-%d'),
            "end_date": l.end_date.strftime('%Y-%m-%d'),
            "reason": l.reason,
            "manager_status": l.manager_status,
            "admin_status": l.admin_status
        } for l in leaves
    ])

@routes.route('/manager/leave/<int:leave_id>/decision', methods=['POST'])
@login_required
@manager_required
def manager_decide_leave(leave_id):
    data = request.json
    decision = data.get('decision')  # 'approved' or 'rejected'
    leave = LeaveRequest.query.get(leave_id)
    if not leave:
        return jsonify({"error": "Leave request not found"}), 404
    emp_profile = EmployeeProfile.query.filter_by(user_id=leave.user_id).first()
    if not emp_profile or emp_profile.manager_id != current_user.id:
        return jsonify({"error": "Not authorized to make decision on this leave"}), 403
    leave.manager_status = decision
    db.session.commit()
    return jsonify({"message": f"Leave {decision} by manager"})

# ---------- EMPLOYEE ROUTES ----------
@routes.route('/employee/profile', methods=['PUT'])
@login_required
def update_employee_profile():
    if current_user.role != 'employee':
        return jsonify({"error": "Only employees can update this profile"}), 403
    profile = EmployeeProfile.query.filter_by(user_id=current_user.id).first()
    if profile:
        data = request.json
        profile.name = data.get('name', profile.name)
        profile.contact_email = data.get('contact_email', profile.contact_email)
        profile.phone_number = data.get('phone_number', profile.phone_number)
        db.session.commit()
        return jsonify({"message": "Employee profile updated successfully"})
    return jsonify({"error": "Profile not found"}), 404

@routes.route('/employee/request_leave', methods=['POST'])
@login_required
def employee_request_leave():
    if current_user.role != 'employee':
        return jsonify({"error": "Only employees can request leave"}), 403
    data = request.json
    new_leave = LeaveRequest(
        user_id=current_user.id,
        start_date=datetime.strptime(data['start_date'], '%Y-%m-%d'),
        end_date=datetime.strptime(data['end_date'], '%Y-%m-%d'),
        reason=data['reason'],
        manager_status='pending',
        admin_status='pending'
    )
    db.session.add(new_leave)
    db.session.commit()
    return jsonify({"message": "Leave request submitted to manager"})


def register_routes(app):
    app.register_blueprint(routes)