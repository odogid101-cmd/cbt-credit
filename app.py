import os
import secrets
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# ================= ADMIN CONFIG =================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("@9064_tech")

# ================= APP =================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "cbtcredit.support@gmail.com")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

if not SENDGRID_API_KEY:
    raise RuntimeError("SENDGRID_API_KEY not set")

# ================= DB CONNECTION =================
def get_db_connection():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor,
        sslmode="require"
    )

# ================= SEND EMAIL =================
def send_email(to_email, subject, body, html=None):
    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=to_email,
        subject=subject,
        plain_text_content=body,
        html_content=html
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print("Email sent:", response.status_code)
        return True
    except Exception as e:
        try:
            print("SendGrid error body:", e.body)
        except:
            print("SendGrid error:", str(e))
        return False

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

# ================= REGISTER =================
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

        return jsonify({
            "message": "Account created successfully",
            "user_id": user["user_id"]
        }), 201

    except IntegrityError as e:
        err = str(e).lower()
        if "username" in err:
            return jsonify({"error": "Username already exists"}), 400
        if "email" in err:
            return jsonify({"error": "Email already exists"}), 400
        return jsonify({"error": "Duplicate entry"}), 400

# ================= LOGIN =================
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
        return jsonify({"error": "Invalid credentials"}), 401

    user.pop("password", None)

    return jsonify({
        "message": "Login successful",
        "user": user
    }), 200

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
        cur.close()
        conn.close()
        return jsonify({"message": "If email exists, code sent"}), 200

    code = str(secrets.randbelow(900000) + 100000)
    expiry = datetime.utcnow() + timedelta(minutes=20)

    cur.execute("""
        UPDATE users
        SET reset_code=%s, reset_code_expiry=%s
        WHERE email=%s
    """, (code, expiry, email))

    conn.commit()
    cur.close()
    conn.close()

    html = f"""
    <div style="font-family: Arial; padding:20px;">
        <h2>Password Reset</h2>
        <p>Your code:</p>
        <h1>{code}</h1>
        <p>Expires in 20 minutes</p>
    </div>
    """

    sent = send_email(
        email,
        "Password Reset Code",
        f"Your code is: {code}",
        html
    )

    if not sent:
        return jsonify({"error": "Failed to send email"}), 500

    return jsonify({"message": "Code sent"}), 200

# ================= VERIFY CODE =================
@app.route("/verify-reset-code", methods=["POST"])
def verify_reset_code():
    data = request.get_json() or {}
    email = data.get("email")
    code = data.get("code")

    if not email or not code:
        return jsonify({"error": "Email and code required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT user_id FROM users
        WHERE email=%s AND reset_code=%s AND reset_code_expiry > NOW()
    """, (email, code))

    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid or expired code"}), 400

    return jsonify({"message": "Code verified"}), 200

# ================= RESET PASSWORD =================
@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}
    email = data.get("email")
    code = data.get("code")
    new_password = data.get("password")

    if not email or not code or not new_password:
        return jsonify({"error": "Missing fields"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT user_id FROM users
        WHERE email=%s AND reset_code=%s AND reset_code_expiry > NOW()
    """, (email, code))

    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({"error": "Invalid or expired code"}), 400

    hashed = generate_password_hash(new_password)

    cur.execute("""
        UPDATE users
        SET password=%s, reset_code=NULL, reset_code_expiry=NULL
        WHERE user_id=%s
    """, (hashed, user["user_id"]))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Password reset successful"}), 200


# ================= ADMIN ROUTES =================
@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if username!= ADMIN_USERNAME:
        return jsonify({"error": "Invalid admin credentials"}), 401
    if not check_password_hash(ADMIN_PASSWORD_HASH, password):
        return jsonify({"error": "Invalid admin credentials"}), 401

    return jsonify({"message": "Login successful"}), 200

@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, full_name, username, email, role, created_at FROM users ORDER BY user_id DESC")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(users), 200

@app.route("/admin/users/<int:user_id>/password", methods=["PUT"])
@admin_required
def admin_reset_user_password(user_id):
    data = request.get_json() or {}
    new_password = data.get("password")
    if not new_password:
        return jsonify({"error": "Password required"}), 400

    hashed = generate_password_hash(new_password)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (hashed, user_id))
    if cur.rowcount == 0:
        cur.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404

    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Password updated successfully"}), 200

@app.route("/admin/users/<int:user_id>/email", methods=["PUT"])
@admin_required
def admin_reset_user_email(user_id):
    data = request.get_json() or {}
    new_email = data.get("email")
    if not new_email:
        return jsonify({"error": "Email required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT user_id FROM users WHERE email=%s AND user_id!=%s", (new_email, user_id))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({"error": "Email already in use"}), 400

    cur.execute("UPDATE users SET email=%s WHERE user_id=%s", (new_email, user_id))
    if cur.rowcount == 0:
        cur.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404

    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Email updated successfully"}), 200

@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE user_id=%s AND role='user'", (user_id,))
    if cur.rowcount == 0:
        cur.close()
        conn.close()
        return jsonify({"error": "User not found or cannot delete admin"}), 404

    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "User deleted successfully"}), 200

# ================= ROOT =================
@app.route("/")
def home():
    return jsonify({"message": "CBT API Running"})

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
