from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
import os
import traceback
import json
from datetime import timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', "$#$^%%*")
app.secret_key = app.config['SECRET_KEY']

app.permanent_session_lifetime = timedelta(days=7)

def get_db():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        database='nyamira',
        cursorclass=pymysql.cursors.DictCursor  # ensures dict results
    )


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'itselmonelsoftware.sol@gmail.com'
app.config['MAIL_PASSWORD'] = 'kwyj cudo jray rniv'
app.config['MAIL_DEFAULT_SENDER'] = 'itselmonelsoftware.sol@gmail.com'

mail = Mail(app)

TOKEN_SERIALIZER = URLSafeTimedSerializer(app.config['SECRET_KEY'])
RESET_TOKEN_SALT = os.environ.get('RESET_TOKEN_SALT', 'reset-password-salt')

@app.route('/')
def index():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'SCDE':
            return redirect(url_for('scde_dashboard'))
        elif role == 'Auditor':
            return redirect(url_for('audit_dashboard'))
    return render_template('index.html')

# Login route
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['role'] = user['role']  

        role = user['role'].strip().lower() if user['role'] else ""

        if role == 'scde':
            return jsonify({'success': True, 'redirect': url_for('scde_dashboard')})
        elif role == 'auditor':
            return jsonify({'success': True, 'redirect': url_for('audit_dashboard')})
        elif role == 'hoi':
            return jsonify({'success': True, 'redirect': url_for('hoi_dashboard')})
        else:
            return jsonify({'success': True, 'redirect': url_for('index')})
    else:
        return jsonify({'success': False, 'message': 'Invalid email or password'})


# Register route
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get("username") or request.form.get("full_name")  # handle both
    email = request.form.get("email")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")
    role = 'User' 

    # Validation: required fields
    if not username or not email or not password or not confirm_password:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': "All fields are required."}), 400
        flash("All fields are required.", "danger")
        return redirect(url_for("index"))

    # Validation: confirm password
    if password != confirm_password:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': "Passwords do not match."}), 400
        flash("Passwords do not match.", "danger")
        return redirect(url_for("index"))

    hashed_pw = generate_password_hash(password)

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_pw, role)
        )
        conn.commit()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'Registration successful. Please login.'})
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("index"))

    except pymysql.IntegrityError:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Email or username already exists'}), 400
        flash("Email or username already exists", "danger")
        return redirect(url_for("index"))

    except Exception as e:
        print("Error in registration:", e)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': "An error occurred during registration."}), 500
        flash("An error occurred during registration.", "danger")
        return redirect(url_for("index"))

    finally:
        cursor.close()
        conn.close()

   

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# SCDE Dashboard (protected)
@app.route('/scde_dashboard')
def scde_dashboard():
    if 'user_id' not in session or session['role'] != 'SCDE':
        return redirect(url_for('index'))
    return render_template('scde_dashboard.html')

# Auditor Dashboard (protected)
@app.route('/audit/dashboard')
def audit_dashboard():
    if 'user_id' not in session or session.get('role').lower() != 'auditor':
        return redirect(url_for('login'))
    return render_template('audit_dashboard.html')

# HOI Dashboard (protected)
@app.route('/hoi/dashboard')
def hoi_dashboard():
    if 'user_id' not in session or session.get('role').lower() != 'hoi':
        return redirect(url_for('login'))
    return render_template('hoi_dashboard.html')


# API to fetch data
@app.route('/api/projects')
def api_projects():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT title, description, icon FROM projects")
    projects = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(projects)

@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    email = request.form.get("email")
    if not email:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': "Email required."}), 400
        flash("Email required.", "danger")
        return redirect(url_for("index"))

    try:
        conn = get_db()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, full_name AS username, email FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
        finally:
            conn.close()

    except Exception as e:
        traceback.print_exc()
        user = None

    if not user:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': "If an account with that email exists, a reset link has been sent."})
        flash("If an account with that email exists, a reset link has been sent.", "info")
        return redirect(url_for("index"))

    token = TOKEN_SERIALIZER.dumps(email, salt=RESET_TOKEN_SALT)
    reset_url = url_for('reset_password', token=token, _external=True)

    subject = "Password Reset Request"
    body = f"Hello {user['username']},\n\nYou requested a password reset. Click the link below to reset your password:\n\n{reset_url}\n\nThe link is valid for 1 hour. If you didn't request this, ignore this email."

    try:
        msg = Message(subject, recipients=[email], body=body)
        mail.send(msg)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': "Reset link sent to your email."})
        flash("Reset link sent to your email.", "success")
    except Exception as e:
        traceback.print_exc()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': "Failed to send reset email. Please try again later."}), 500
        flash("Failed to send reset email. Please try again later.", "danger")

    return redirect(url_for("index"))

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = TOKEN_SERIALIZER.loads(token, salt=RESET_TOKEN_SALT, max_age=3600)
    except SignatureExpired:
        flash("The reset link has expired. Please request a new one.", "danger")
        return redirect(url_for("index"))
    except Exception:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("index"))

    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not password or password != confirm_password:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': "Passwords do not match or are empty."}), 400
            flash("Passwords do not match or are empty.", "danger")
            return redirect(url_for("index", token=token))

        hashed_pw = generate_password_hash(password)

        try:
            conn = get_db()
            try:
                conn.autocommit = False
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                conn.close()
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'message': "Password reset successfully. Please log in."})
            flash("Password reset successfully. Please log in.", "success")
            return redirect(url_for("index", reset="success"))
        except Exception as e:
            traceback.print_exc()
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': "Error resetting password."}), 500
            flash("Error resetting password.", "danger")
            return redirect(url_for("index", token=token))

    # GET request → redirect to index with token to open modal
    return redirect(url_for("index", token=token))

if __name__ == '__main__':
    app.run(debug=True)