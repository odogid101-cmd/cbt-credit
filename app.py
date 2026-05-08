import os
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# ================= ADMIN CONFIG =================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("@9064_tech")

# ================= APP =================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

# ================= MAIL CONFIG =================
app.config['MAIL_SERVER'] = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('SMTP_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('SMTP_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('FROM_EMAIL', 'cbt-support@gmail.com')
mail = Mail(app)

FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')

# ================= DB CONNECTION =================
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor, sslmode="require")

# ================= ADMIN GUARD =================
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        data = request.get_json(silent=True) or {}
        password = data.get("admin_password") or request.args.get("admin_password")
        if not password or not check_password_hash(ADMIN_PASSWORD_HASH, password):
            return jsonify({"error": "Admin authorization required"}), 403
        return f(*args, **kwargs)
    return wrapper

# ================= INIT DB =================
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # USERS table - cleaned, no subjects/questions
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            full_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
            created_at TIMESTAMP DEFAULT NOW(),
            reset_token TEXT,
            reset_token_expiry TIMESTAMP,
            credential_id TEXT,
            public_key TEXT,
            sign_count INT DEFAULT 0
        );
    """)
    conn.commit()

    # Create default admin if none exists
    cur.execute("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1")
    if not cur.fetchone():
        admin_pass = generate_password_hash('@9064_tech')
        cur.execute("""
            INSERT INTO users (full_name, username, email, password, role)
            VALUES (%s, %s, %s, %s, %s)
        """, ('Admin', 'admin', 'admin@example.com', admin_pass, 'admin'))
        conn.commit()

    # RESULTS table - keep this for exam results
    cur.execute("""
        CREATE TABLE IF NOT EXISTS results (
            result_id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            score INT NOT NULL,
            total_questions INT NOT NULL,
            submitted_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()

    cur.close()
    conn.close()

init_db()

# ================= ADMIN LOGIN =================
@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    if data.get("username")!= ADMIN_USERNAME:
        return jsonify({"error": "Invalid admin credentials"}), 401
    if not check_password_hash(ADMIN_PASSWORD_HASH, data.get("password", "")):
        return jsonify({"error": "Invalid admin credentials"}), 401
    return jsonify({"message": "Admin login successful"}), 200

# ================= ADMIN USERS =================
@app.route("/admin/users", methods=["GET"])
@admin_required
def get_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT user_id, full_name, username, email, role, created_at
        FROM users ORDER BY user_id DESC
    """)
    users = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(users), 200

@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    if user_id == 1:
        return jsonify({"error": "Cannot delete main admin"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE user_id=%s RETURNING user_id", (user_id,))
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not deleted:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": "User deleted"}), 200

@app.route("/admin/users/<int:user_id>/role", methods=["PUT"])
@admin_required
def update_user_role(user_id):
    data = request.get_json() or {}
    new_role = data.get("role")
    if new_role not in ['user', 'admin']:
        return jsonify({"error": "Role must be user or admin"}), 400
    if user_id == 1:
        return jsonify({"error": "Cannot change main admin role"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role=%s WHERE user_id=%s RETURNING user_id, username, role",
                (new_role, user_id))
    updated = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not updated:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": "Role updated", "user": updated}), 200

@app.route("/admin/users/<int:user_id>/password", methods=["PUT"])
@admin_required
def admin_reset_password(user_id):
    data = request.get_json() or {}
    new_password = data.get("password")
    if not new_password:
        return jsonify({"error": "Password required"}), 400
    if user_id == 1:
        return jsonify({"error": "Cannot change main admin password"}), 400

    hashed = generate_password_hash(new_password)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password=%s WHERE user_id=%s RETURNING user_id",
                (hashed, user_id))
    updated = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not updated:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"message": "Password updated successfully"}), 200

# ================= USER AUTH =================
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    required = ["full_name", "username", "email", "password"]
    if not all(data.get(x) for x in required):
        return jsonify({"error": "Missing fields"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (full_name, username, email, password, role)
            VALUES (%s,%s,%s,%s,%s) RETURNING user_id
        """, (
            data["full_name"],
            data["username"],
            data["email"],
            generate_password_hash(data["password"]),
            'user'
        ))
        user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Account created successfully", "user_id": user["user_id"]}), 201
    except IntegrityError as e:
        err_msg = str(e).lower()
        if "username" in err_msg:
            return jsonify({"error": "Username already exists"}), 400
        elif "email" in err_msg:
            return jsonify({"error": "Email already exists"}), 400
        return jsonify({"error": "Username or email already exists"}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    login_field = data.get("login")
    password = data.get("password")

    if not login_field or not password:
        return jsonify({"error": "Missing credentials"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM users WHERE username=%s OR email=%s",
        (login_field, login_field)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username/email or password"}), 401

    user.pop("password", None)
    return jsonify({"message": "Login successful", "user": user}), 200

# ================= FORGOT PASSWORD =================
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json() or {}
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    if not user:
        # Don't reveal if email exists
        return jsonify({"message": "If email exists, reset link has been sent"}), 200

    token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(minutes=30)

    cur.execute(
        "UPDATE users SET reset_token=%s, reset_token_expiry=%s WHERE email=%s",
        (token, expiry, email)
    )
    conn.commit()
    cur.close()
    conn.close()

    reset_link = f"{FRONTEND_URL}/reset-password?token={token}"

    try:
        msg = Message(
            subject="Password Reset Request",
            recipients=[email],
            body=f"Click this link to reset your password: {reset_link}\n\nThis link expires in 30 minutes."
        )
        mail.send(msg)
    except Exception as e:
        return jsonify({"error": "Failed to send email"}), 500

    return jsonify({"message": "If email exists, reset link has been sent"}), 200

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}
    token = data.get("token")
    new_password = data.get("password")

    if not token or not new_password:
        return jsonify({"error": "Token and password required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT user_id FROM users WHERE reset_token=%s AND reset_token_expiry > NOW()",
        (token,)
    )
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({"error": "Invalid or expired token"}), 400

    hashed = generate_password_hash(new_password)
    cur.execute(
        "UPDATE users SET password=%s, reset_token=NULL, reset_token_expiry=NULL WHERE user_id=%s",
        (hashed, user["user_id"])
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Password reset successful"}), 200

# ================= FINGERPRINT PLACEHOLDER =================
@app.route("/webauthn/register/begin", methods=["POST"])
def webauthn_register_begin():
    # Placeholder for WebAuthn registration start
    # Requires 'webauthn' library and more setup
    return jsonify({"error": "WebAuthn not implemented yet"}), 501

@app.route("/webauthn/login/begin", methods=["POST"])
def webauthn_login_begin():
    # Placeholder for WebAuthn login start
    return jsonify({"error": "WebAuthn not implemented yet"}), 501

# ================= OTHER ROUTES =================
@app.route("/")
def home():
    return jsonify({"message": "CBT API Running"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
