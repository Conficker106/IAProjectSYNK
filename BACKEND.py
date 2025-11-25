# ==========================================
# 1. IMPORTS & SETUP
# ==========================================
import os
import logging
import random
import smtplib
import datetime
import re
from collections import Counter
from datetime import timedelta
from functools import wraps
from io import BytesIO
from threading import Thread
import time

# Third-party imports
from flask import Flask, request, session, redirect, url_for, render_template, flash, make_response
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
from bson import ObjectId
from xhtml2pdf import pisa
from dotenv import load_dotenv
import google.generativeai as genai
from werkzeug.middleware.proxy_fix import ProxyFix
from email.mime.text import MIMEText

# Load secrets from .env file
load_dotenv()

# Initialize Flask App
app = Flask(__name__)

# ==========================================
# 2. CONFIGURATION
# ==========================================

# --- Security Config ---
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)

# Cookie Security (Set True in Prod)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# --- Extensions Setup ---
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- PERFORMANCE FIX: Persistent Logging Handler ---
activity_logger = logging.getLogger('activity_logger')
activity_logger.setLevel(logging.INFO)
if not activity_logger.handlers:
    file_handler = logging.FileHandler('user_activity.log')
    file_handler.setFormatter(logging.Formatter('%(message)s'))
    activity_logger.addHandler(file_handler)

# --- Encryption ---
KEY_FILE_PATH = os.environ.get("ENCRYPTION_KEY_PATH", "encryption_key.key")


def load_or_create_key():
    os.makedirs(os.path.dirname(os.path.abspath(KEY_FILE_PATH)) or '.', exist_ok=True)
    if os.path.exists(KEY_FILE_PATH):
        with open(KEY_FILE_PATH, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        try:
            with open(KEY_FILE_PATH, "wb") as key_file:
                key_file.write(key)
        except Exception as e:
            print(f"Warning: Could not set key file permissions: {e}")
        return key


encryption_key = load_or_create_key()
cipher = Fernet(encryption_key)

# --- AI Setup ---
GENAI_API_KEY = os.environ.get("GENAI_API_KEY")
if GENAI_API_KEY: genai.configure(api_key=GENAI_API_KEY)


def get_gemini_model():
    if not GENAI_API_KEY: return None
    preferred_models = ['gemini-2.5-flash']
    try:
        available = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        for model_name in preferred_models:
            full_name = f"models/{model_name}"
            if full_name in available: return genai.GenerativeModel(model_name)
        if available: return genai.GenerativeModel(available[0].replace('models/', ''))
        return None
    except:
        return None


# ==========================================
# 3. MODELS & UTILS
# ==========================================

class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.username = user_doc['username']
        self.role = user_doc['role']
        self.email = user_doc['email']
        self.token_version = user_doc.get('token_version', 0)


@login_manager.user_loader
def load_user(user_id):
    if not ObjectId.is_valid(user_id): return None
    user_doc = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_doc) if user_doc else None


# --- SOC-Grade Logging Helper (With IP) ---
def log_access(username, role, action):
    """
    Logs every action with timestamp, IP ADDRESS, user, role, and action detail.
    """
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')

    # Get IP Address (Handles Proxies via ProxyFix)
    ip_address = request.remote_addr if request else "Unknown"

    clean_user = str(username).replace('\n', '').replace('\r', '')
    clean_action = str(action).replace('\n', '').replace('\r', '')

    # FORMAT: [Time] IP | User | Role | Action
    log_message = f"[{timestamp}] IP: {ip_address} | User: {clean_user} | Role: {role} | Action: {clean_action}"

    activity_logger.info(log_message)
    # Optional console print
    # print(log_message)


# --- Threaded Email Helper ---
def send_email_task(app_context, to_email, subject, body):
    with app_context:
        try:
            email_addr = os.environ.get("EMAIL_ADDRESS")
            email_pass = os.environ.get("EMAIL_PASSWORD")
            if not email_addr or not email_pass: return

            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = email_addr
            msg["To"] = to_email

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(email_addr, email_pass)
                server.sendmail(email_addr, to_email, msg.as_string())
            print(f"Background Email sent to {to_email}")
        except Exception as e:
            print(f"Failed to send email: {str(e)}")


def send_email(to_email, subject, body):
    app_ctx = app.app_context()
    email_thread = Thread(target=send_email_task, args=(app_ctx, to_email, subject, body))
    email_thread.start()


def send_otp(email, otp):
    send_email(email, "Your OTP for Login", f"Your OTP code is: {otp}\n\nDo not share this with anyone.")
    flash(f"OTP sent to {email}.", "otp_success")
    return redirect(url_for('verify_otp'))


def is_password_strong(password):
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return re.match(pattern, password)


# --- Decorators ---
roles_permissions = {
    "admin": ["view_all", "edit_all"],
    "doctor": ["view_patient", "edit_patient"],
    "nurse": ["view_patient", "add_notes", "view_nursing_notes"],
    "patient": ["view_self", "view_nursing_notes"]
}


def role_required(required_permissions):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if current_user.is_authenticated:
                user_role = current_user.role
                permissions = roles_permissions.get(user_role, [])
                if any(rp in permissions for rp in required_permissions):
                    return f(*args, **kwargs)
                log_access(current_user.username, current_user.role, f"Unauthorized Access Attempt: {request.endpoint}")
                return render_template("unauthorized.html")
            return redirect(url_for('login'))

        return wrapper

    return decorator


@app.before_request
def before_request_checks():
    user_agent = request.headers.get('User-Agent', '').lower()
    if 'python-requests' in user_agent:
        log_access("Unknown", "Bot", "Blocked Scraper Access (User-Agent)")
        return "<h1>403 Forbidden</h1>", 403

    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)
    if current_user.is_authenticated:
        if 'token_version' in session:
            if session['token_version'] != current_user.token_version:
                logout_user()
                session.clear()
                flash("Session expired due to role change.", "warning")
                return redirect(url_for('login'))


def auto_unlock_accounts():
    while True:
        try:
            current_time = datetime.datetime.now()
            mongo.db.users.update_many(
                {'locked_until': {'$ne': None, '$lte': current_time}},
                {'$set': {'failed_attempts': 0, 'locked_until': None}}
            )
        except Exception:
            pass
        time.sleep(10)


unlock_thread = Thread(target=auto_unlock_accounts, daemon=True)
unlock_thread.start()


# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    if current_user.is_authenticated: log_access(current_user.username, current_user.role, f"404 Error: {request.url}")
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    if current_user.is_authenticated: log_access(current_user.username, current_user.role, f"500 Error: {request.url}")
    return render_template('500.html'), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('429.html', error=e.description), 429


# ==========================================
# 4. AUTH ROUTES
# ==========================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        if request.form.get('website'): return redirect(url_for('login'))

        data = request.form
        username = data.get('username')
        email = data.get('email').strip()
        password = data.get('password')
        role = "patient"

        existing_user = mongo.db.users.find_one({
            "email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}
        })

        if existing_user:
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))

        if mongo.db.users.find_one({"username": username}):
            flash("Username taken.", "warning")
            return redirect(url_for('register'))

        if not is_password_strong(password):
            flash("Password too weak.", "warning")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        mongo.db.users.insert_one({
            'username': username, 'email': email.lower(), 'password': hashed_pw, 'role': role,
            'failed_attempts': 0, 'locked_until': None, 'token_version': 0
        })

        log_access(username, role, "Registered new account")
        send_email(email, "Welcome!", f"Hello {username},\nYour account is created.")
        flash("Registered successfully", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        if request.form.get('honeypot_field'):
            log_access("Unknown", "Bot", "Honeypot Triggered on Login")
            return "<h1>400 Bad Request</h1>", 400

        data = request.form
        username = data.get('username', '')
        password = data.get('password', '')

        user_doc = mongo.db.users.find_one({'username': username})

        if user_doc:
            if user_doc.get('locked_until') and user_doc['locked_until'] > datetime.datetime.now():
                time_remaining = user_doc['locked_until'] - datetime.datetime.now()
                seconds_remaining = int(time_remaining.total_seconds())
                flash(f"⚠️ Account Locked! Wait {seconds_remaining} seconds.", "danger")
                log_access(username, user_doc['role'], "Login Attempt on Locked Account")
                return render_template('login.html')

            if bcrypt.check_password_hash(user_doc['password'], password):
                mongo.db.users.update_one({'_id': user_doc['_id']},
                                          {'$set': {'failed_attempts': 0, 'locked_until': None}})
                otp = str(random.randint(100000, 999999))
                session['otp'] = otp
                session['user_id'] = str(user_doc['_id'])
                log_access(username, user_doc['role'], "Primary Auth Success - Sending OTP")
                send_otp(user_doc['email'], otp)
                return redirect(url_for('verify_otp'))
            else:
                new_attempts = user_doc.get('failed_attempts', 0) + 1
                if new_attempts >= 3:
                    lockout = datetime.datetime.now() + timedelta(seconds=60)
                    mongo.db.users.update_one({'_id': user_doc['_id']},
                                              {'$set': {'failed_attempts': new_attempts, 'locked_until': lockout}})
                    log_access(username, user_doc['role'], "Account Locked - 3 Failed Attempts")
                    send_email(user_doc['email'], "Security Alert", "Account Locked.")
                    flash("🔒 Account Locked for 60 seconds.", "danger")
                else:
                    mongo.db.users.update_one({'_id': user_doc['_id']}, {'$set': {'failed_attempts': new_attempts}})
                    log_access(username, user_doc['role'], f"Failed Login Attempt {new_attempts}/3")
                    flash(f"❌ Invalid credentials. Attempts: {new_attempts}/3", "warning")
        else:
            log_access(username, "Unknown", "Failed Login - User Not Found")
            flash("❌ Invalid credentials.", "danger")

    return render_template('login.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        input_otp = request.form.get('otp')
        if 'user_id' not in session: return redirect(url_for('login'))

        user_doc = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
        if not user_doc: return redirect(url_for('login'))

        if input_otp == session.get('otp'):
            user = User(user_doc)
            login_user(user)
            session['token_version'] = user.token_version
            session.pop('otp')
            log_access(user.username, user.role, "2FA Success - Logged In")
            return redirect(url_for('dashboard'))

        log_access(user_doc['username'], user_doc['role'], "2FA Failed - Invalid OTP")
        flash("Invalid OTP.", "otp_error")
    return render_template('verify_otp.html')


@app.route('/logout')
@login_required
def logout():
    log_access(current_user.username, current_user.role, "Logged Out")
    logout_user()
    session.clear()
    return redirect(url_for('login'))


# ==========================================
# 5. GENERAL ROUTES
# ==========================================

@app.route('/dashboard')
@login_required
def dashboard():
    log_access(current_user.username, current_user.role, "Accessed Dashboard")
    return render_template('dashboard.html', role=current_user.role)


@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        new_email = request.form.get('email').strip()
        new_password = request.form.get('password')
        update_data = {}

        if new_email:
            existing = mongo.db.users.find_one({"email": {"$regex": f"^{re.escape(new_email)}$", "$options": "i"}})
            if existing and existing['_id'] != ObjectId(current_user.id):
                flash("Email in use.", "danger")
                return redirect(url_for('update_profile'))
            update_data['email'] = new_email.lower()

        if new_password:
            if not is_password_strong(new_password):
                flash("Weak password.", "warning")
                return redirect(url_for('update_profile'))
            update_data['password'] = bcrypt.generate_password_hash(new_password).decode('utf-8')

        if update_data:
            mongo.db.users.update_one({'_id': ObjectId(current_user.id)}, {'$set': update_data})
            log_access(current_user.username, current_user.role, "Updated Profile Credentials")
            send_email(current_user.email, "Profile Updated", "Your credentials were updated.")
            flash("Profile updated!", "success")

        return redirect(url_for('dashboard'))

    log_access(current_user.username, current_user.role, "Viewed Profile Update Page")
    return render_template('update_profile.html')


@app.route('/export_records_pdf')
@login_required
@role_required(['view_self'])
@limiter.limit("5 per hour")
def export_records_pdf():
    records = mongo.db.records.find({'owner': current_user.username})
    decrypted_records = []
    for r in records:
        try:
            text = cipher.decrypt(r["data"]).decode()
        except:
            text = "Error"
        decrypted_records.append(
            {"date": r.get('created_at', 'N/A'), "doctor": r.get('assigned_doctor', 'N/A'), "details": text})

    rendered = render_template('pdf_template.html', user=current_user.username, records=decrypted_records)
    pdf = BytesIO()
    pisa.CreatePDF(BytesIO(rendered.encode('utf-8')), pdf)
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=Records_{current_user.username}.pdf'
    log_access(current_user.username, current_user.role, "Exported/Downloaded Medical Records PDF")
    return response


# ==========================================
# 6. DOCTOR ROUTES
# ==========================================

@app.route('/appointments')
@login_required
@role_required(['view_patient'])
def view_appointments():
    log_access(current_user.username, current_user.role, "Viewed Assigned Appointments List")
    appointments = mongo.db.appointments.find({'doctor': current_user.username})
    return render_template("appointments.html", appointments=appointments)


@app.route('/assign_nurse', methods=['GET', 'POST'])
@login_required
@role_required(['edit_patient'])
def assign_nurse():
    if request.method == 'POST':
        patient = request.form.get('patient')
        nurse = request.form.get('nurse')
        mongo.db.appointments.update_one({"patient": patient, "doctor": current_user.username},
                                         {"$set": {"nurse_assigned": nurse}})

        log_access(current_user.username, current_user.role, f"Assigned Nurse {nurse} to Patient {patient}")
        flash("Nurse assigned.", "success")
        return redirect(url_for('dashboard'))

    log_access(current_user.username, current_user.role, "Viewed Nurse Assignment Page")
    approved = mongo.db.appointments.find({"doctor": current_user.username, "status": "approved"})
    nurses = mongo.db.users.find({"role": "nurse"}, {"username": 1})
    return render_template('assign_nurse.html', patients=approved, nurses=nurses)


@app.route('/add_record', methods=['GET', 'POST'])
@login_required
@role_required(['edit_patient'])
def add_record():
    if current_user.role != 'doctor': return redirect(url_for('dashboard'))
    patients = mongo.db.appointments.find({"doctor": current_user.username, "status": "approved"})
    patient_list = [p["patient"] for p in patients]

    if request.method == 'POST':
        selected_patient = request.form.get('patient')
        record_data = request.form.get('record')
        encrypted_data = cipher.encrypt(record_data.encode())
        mongo.db.records.insert_one(
            {'owner': selected_patient, 'patient_name': selected_patient, 'data': encrypted_data,
             'assigned_doctor': current_user.username, 'created_at': datetime.datetime.now()})

        log_access(current_user.username, current_user.role, f"Created Medical Record for {selected_patient}")
        flash("Record added.", "success")
        return redirect(url_for('dashboard'))

    log_access(current_user.username, current_user.role, "Viewed Add Record Page")
    return render_template('add_record.html', patients=patient_list)


@app.route('/delete_records', methods=['POST'])
@login_required
@role_required(['edit_patient'])
def delete_records():
    selected = request.form.getlist('record_ids')
    deleted_count = 0

    for rid in selected:
        result = mongo.db.records.delete_one({
            "_id": ObjectId(rid),
            "assigned_doctor": current_user.username
        })
        deleted_count += result.deleted_count

    if deleted_count > 0:
        log_access(current_user.username, current_user.role, f"Deleted {deleted_count} Medical Records")
        flash(f"{deleted_count} records deleted.", "success")
    else:
        log_access(current_user.username, current_user.role,
                   f"Failed Delete Attempt (Potential IDOR) on IDs: {selected}")
        flash("No records deleted. Authorization check failed.", "danger")

    return redirect(url_for('view_records'))


@app.route('/generate_ai_record', methods=['POST'])
@login_required
@role_required(['edit_patient'])
def generate_ai_record():
    try:
        data = request.get_json()
        model = get_gemini_model()
        if not model: return {"error": "No AI model available."}, 500
        prompt = f"SYSTEM: Convert to SOAP be concise. INPUT: {data.get('notes', '')}"
        response = model.generate_content(prompt)
        log_access(current_user.username, current_user.role, "Invoked AI SOAP Note Generator")
        return {"soap_note": response.text}
    except Exception as e:
        return {"error": str(e)}, 500


# ==========================================
# 7. NURSE ROUTES
# ==========================================

@app.route('/nurse_records')
@login_required
@role_required(['view_patient'])
def nurse_records_view():
    log_access(current_user.username, current_user.role, "Viewed Accessible Patient Records (Nurse View)")
    assigned = mongo.db.appointments.find({"nurse_assigned": current_user.username})
    p_list = [p["patient"] for p in assigned]
    records = mongo.db.records.find({"owner": {"$in": p_list}})
    d_recs = []
    for r in records:
        try:
            d = cipher.decrypt(r["data"]).decode()
        except:
            d = "Error"
        d_recs.append({"patient": r["owner"], "data": d, "assigned_doctor": r.get("assigned_doctor")})
    return render_template("nurse_records.html", records=d_recs)


@app.route('/nurse_appointments')
@login_required
@role_required(['view_patient'])
def nurse_appointments():
    log_access(current_user.username, current_user.role, "Viewed All Appointments Schedule")
    appointments = mongo.db.appointments.find({})
    return render_template("nurse_appointments.html", appointments=appointments)


@app.route('/add_nursing_note', methods=['GET', 'POST'])
@login_required
@role_required(['add_notes'])
def add_nursing_note():
    if request.method == 'POST':
        mongo.db.nursing_notes.insert_one({
            "nurse": current_user.username, "patient": request.form.get('patient'),
            "note": cipher.encrypt(request.form.get('note').encode()),
            "timestamp": datetime.datetime.now()
        })
        log_access(current_user.username, current_user.role, f"Added Nursing Note for {request.form.get('patient')}")
        flash("Note added.", "success")
        return redirect(url_for('dashboard'))

    log_access(current_user.username, current_user.role, "Viewed Add Nursing Note Page")
    patients = list(set([p["patient"] for p in mongo.db.appointments.find({"nurse_assigned": current_user.username})]))
    return render_template("add_nursing_note.html", patients=patients)


# ==========================================
# 8. PATIENT ROUTES
# ==========================================

@app.route('/book_appointment', methods=['GET', 'POST'])
@login_required
@role_required(['view_self'])
def book_appointment():
    if request.method == 'POST':
        doc = request.form.get('doctor')
        mongo.db.appointments.insert_one({
            "patient": current_user.username, "doctor": doc,
            "date": request.form.get('date'), "time": request.form.get('time'), "status": "pending"
        })
        doc_user = mongo.db.users.find_one({"username": doc})
        if doc_user: send_email(doc_user['email'], "New Appointment", "You have a new request.")

        log_access(current_user.username, current_user.role, f"Booked Appointment with {doc}")
        flash("Request sent!", "success")
        return redirect(url_for('dashboard'))

    log_access(current_user.username, current_user.role, "Viewed Book Appointment Page")
    doctors = mongo.db.users.find({"role": "doctor"}, {"username": 1})
    return render_template("book_appointment.html", doctors=doctors)


@app.route('/my_appointments')
@login_required
@role_required(['view_self'])
def my_appointments():
    log_access(current_user.username, current_user.role, "Viewed Personal Appointments")
    appointments = mongo.db.appointments.find({'patient': current_user.username})
    return render_template("my_appointments.html", appointments=appointments)


@app.route('/approve_appointment/<appointment_id>', methods=['POST'])
@login_required
@role_required(['view_patient'])
def approve_appointment(appointment_id):
    mongo.db.appointments.update_one({"_id": ObjectId(appointment_id)}, {"$set": {"status": "approved"}})
    log_access(current_user.username, current_user.role, f"Approved Appointment {appointment_id}")
    flash("Approved!", "success")
    return redirect(url_for('view_appointments'))


@app.route('/reject_appointment/<appointment_id>', methods=['POST'])
@login_required
@role_required(['view_patient'])
def reject_appointment(appointment_id):
    mongo.db.appointments.update_one({"_id": ObjectId(appointment_id)}, {"$set": {"status": "rejected"}})
    log_access(current_user.username, current_user.role, f"Rejected Appointment {appointment_id}")
    flash("Rejected!", "danger")
    return redirect(url_for('view_appointments'))


# ==========================================
# 9. SHARED ROUTES
# ==========================================

@app.route('/view_records')
@login_required
@role_required(['view_patient', 'view_self'])
@limiter.limit("5 per minute")
def view_records():
    log_access(current_user.username, current_user.role, "Viewed/Accessed Medical Records")

    if current_user.role == "doctor":
        records = mongo.db.records.find({'assigned_doctor': current_user.username})
        template_name = "doc_records.html"
    elif current_user.role == "nurse":
        records = mongo.db.records.find({})
        template_name = "nurse_records.html"
    elif current_user.role == "patient":
        records = mongo.db.records.find({'owner': current_user.username})
        template_name = "patient_records.html"
    else:
        return redirect(url_for('dashboard'))

    decrypted = []
    for r in records:
        try:
            d = cipher.decrypt(r["data"]).decode()
        except:
            d = "Error"
        decrypted.append({"_id": str(r["_id"]), "patient": r.get("patient_name"), "data": d,
                          "assigned_doctor": r.get("assigned_doctor"), "created_at": r.get("created_at")})
    return render_template(template_name, records=decrypted)


@app.route('/view_nursing_notes')
@login_required
@role_required(['view_nursing_notes'])
def view_nursing_notes():
    log_access(current_user.username, current_user.role, "Viewed Nursing Notes")
    query = {"patient": current_user.username} if current_user.role == 'patient' else {"patient": {
        "$in": [p["patient"] for p in mongo.db.appointments.find({"nurse_assigned": current_user.username})]}}
    notes = mongo.db.nursing_notes.find(query)
    d_notes = []
    for n in notes:
        try:
            d = cipher.decrypt(n["note"]).decode()
        except:
            d = "Error"
        d_notes.append({"nurse": n["nurse"], "patient": n["patient"], "note": d, "timestamp": n["timestamp"]})
    return render_template("nurse_notes.html", notes=d_notes)


# ==========================================
# 10. ADMIN ROUTES
# ==========================================

@app.route('/manage_users')
@login_required
@role_required(['view_all'])
def manage_users():
    log_access(current_user.username, current_user.role, "Viewed User Management Console")
    users = list(mongo.db.users.find({}, {"_id": 1, "username": 1, "email": 1, "role": 1}))
    return render_template('manage_users.html', users=users)


@app.route('/create_staff', methods=['GET', 'POST'])
@login_required
@role_required(['edit_all'])
def create_staff():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email').strip()
        password = request.form.get('password')
        role = request.form.get('role')

        if role not in ['doctor', 'nurse', 'admin']:
            flash("Invalid role.", "danger")
            return redirect(url_for('create_staff'))

        if mongo.db.users.find_one({"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}}):
            flash("Email exists.", "danger")
            return redirect(url_for('create_staff'))

        if not is_password_strong(password):
            flash("Weak password.", "warning")
            return redirect(url_for('create_staff'))

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        mongo.db.users.insert_one({
            'username': username, 'email': email.lower(), 'password': hashed, 'role': role,
            'failed_attempts': 0, 'locked_until': None, 'token_version': 0
        })

        log_access(current_user.username, current_user.role, f"Created Staff Account: {username} ({role})")
        send_email(email, "Account Created", f"Role: {role}\nPW: {password}")
        flash(f"Created {role}: {username}", "success")
        return redirect(url_for('manage_users'))

    log_access(current_user.username, current_user.role, "Viewed Create Staff Page")
    return render_template('create_staff.html')


@app.route('/update_user_role/<user_id>', methods=['POST'])
@login_required
@role_required(['view_all'])
def update_user_role(user_id):
    if not ObjectId.is_valid(user_id):
        flash("Invalid User ID", "danger")
        return redirect(url_for('manage_users'))

    new_role = request.form.get('role')

    user_doc = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not user_doc:
        flash("User not found.", "danger")
        return redirect(url_for('manage_users'))

    old_role = user_doc['role']
    target_username = user_doc['username']

    mongo.db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": new_role}, "$inc": {"token_version": 1}}
    )

    truncation_msg = ""

    # CASE A: Doctor is demoted/changed
    if old_role == 'doctor' and new_role != 'doctor':
        d_recs = mongo.db.records.delete_many({"assigned_doctor": target_username})
        d_appts = mongo.db.appointments.delete_many({"doctor": target_username})
        truncation_msg = f" | Cleaned up: {d_recs.deleted_count} records, {d_appts.deleted_count} appointments."

    # CASE B: Nurse is promoted/changed
    elif old_role == 'nurse' and new_role != 'nurse':
        d_notes = mongo.db.nursing_notes.delete_many({"nurse": target_username})
        u_appts = mongo.db.appointments.update_many(
            {"nurse_assigned": target_username},
            {"$set": {"nurse_assigned": None}}
        )
        truncation_msg = f" | Cleaned up: {d_notes.deleted_count} notes, unassigned from {u_appts.modified_count} appointments."

    log_access(current_user.username, current_user.role,
               f"Updated role of {target_username} to {new_role}{truncation_msg}")
    send_email(user_doc['email'], "Role Updated", f"Your role is now: {new_role}")

    flash(f"Role updated for {target_username}.{truncation_msg}", "success")
    return redirect(url_for('manage_users'))


@app.route('/delete_user/<user_id>', methods=['POST'])
@login_required
@role_required(['view_all'])
def delete_user(user_id):
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        mongo.db.users.delete_one({"_id": ObjectId(user_id)})
        log_access(current_user.username, current_user.role, f"Permanently Deleted User: {user['username']}")
        send_email(user['email'], "Account Deleted", "Your account has been removed.")
    flash("User deleted.", "success")
    return redirect(url_for('manage_users'))


@app.route('/view_logs')
@login_required
@role_required(['view_all'])
def view_logs():
    log_access(current_user.username, current_user.role, "Inspected System Logs")
    logs = []
    if os.path.exists("user_activity.log"):
        with open("user_activity.log", "r") as f: logs = f.readlines()
    return render_template("view_logs.html", logs=logs)


@app.route('/logs_dashboard')
@login_required
@role_required(['view_all'])
def logs_dashboard():
    log_access(current_user.username, current_user.role, "Viewed SIEM/Logs Dashboard")
    role_counts = Counter()
    action_counts = Counter()
    total_events = 0
    unique_users = set()

    if os.path.exists("user_activity.log"):
        log_pattern = re.compile(r"User: (.*?) \| Role: (.*?) \| Action: (.*)")
        with open("user_activity.log", "r") as f:
            for line in f:
                match = log_pattern.search(line)
                if match:
                    total_events += 1
                    unique_users.add(match.group(1))
                    role_counts[match.group(2)] += 1
                    action_counts[match.group(3)] += 1

    return render_template("logs_dashboard.html", total_events=total_events, unique_users=len(unique_users),
                           role_counts=role_counts, action_counts=action_counts)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context='adhoc')