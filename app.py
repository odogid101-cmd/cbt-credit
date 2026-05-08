import os
import random
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail, Message
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

# ================= ADMIN CONFIG =================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("@9064_tech")

# ================= APP =================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

# ================= MAIL CONFIG =================
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('FROM_EMAIL', 'cbt-support@gmail.com')
mail = Mail(app)

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

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            full_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
            created_at TIMESTAMP DEFAULT NOW(),
            reset_code TEXT,
            reset_code_expiry TIMESTAMP,
            credential_id TEXT,
            public_key TEXT,
            sign_count INT DEFAULT 0
        );
    """)
    conn.commit()

    cur.execute("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1")
    if not cur.fetchone():
        admin_pass = generate_password_hash('@9064_tech')
        cur.execute("""
            INSERT INTO users (full_name, username, email, password, role)
            VALUES (%s, %s, %s, %s, %s)
        """, ('Admin', 'admin', 'admin@example.com', admin_pass, 'admin'))
        conn.commit()

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

# ================= FORGOT PASSWORD - CODE FLOW =================
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
        return jsonify({"message": "If email exists, code has been sent"}), 200

    # Generate 6-digit code
    code = str(random.randint(100000, 999))
    expiry = datetime.utcnow() + timedelta(minutes=10)

    cur.execute(
        "UPDATE users SET reset_code=%s, reset_code_expiry=%s WHERE email=%s",
        (code, expiry, email)
    )
    conn.commit()
    cur.close()
    conn.close()

    try:
        msg = Message(
            subject="Password Reset Code",
            recipients=[email],
            body=f"Your password reset code is: {code}\n\nThis code expires in 10 minutes."
        )
        mail.send(msg)
    except Exception as e:
        return jsonify({"error": "Failed to send email"}), 500

    return jsonify({"message": "Code sent to email"}), 200

@app.route("/verify-reset-code", methods=["POST"])
def verify_reset_code():
    data = request.get_json() or {}
    email = data.get("email")
    code = data.get("code")

    if not email or not code:
        return jsonify({"error": "Email and code required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT user_id FROM users WHERE email=%s AND reset_code=%s AND reset_code_expiry > NOW()",
        (email, code)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid or expired code"}), 400

    return jsonify({"message": "Code verified"}), 200

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}
    email = data.get("email")
    code = data.get("code")
    new_password = data.get("password")

    if not email or not code or not new_password:
        return jsonify({"error": "Email, code and password required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT user_id FROM users WHERE email=%s AND reset_code=%s AND reset_code_expiry > NOW()",
        (email, code)
    )
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({"error": "Invalid or expired code"}), 400

    hashed = generate_password_hash(new_password)
    cur.execute(
        "UPDATE users SET password=%s, reset_code=NULL, reset_code_expiry=NULL WHERE user_id=%s",
        (hashed, user["user_id"])
    )
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Password reset successful"}), 200

# ================= OTHER ROUTES =================
@app.route("/")
def home():
    return jsonify({"message": "CBT API Running"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
