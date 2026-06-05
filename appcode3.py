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
ADMIN_PASSWORD_HASH = generate_password_hash("admin")

# ================= APP =================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "allow_headers": ["Content-Type", "X-Admin-Password"]}}, supports_credentials=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "cbtcredit.support@gmail.com")
DEFAULT_AVATAR = "https://i.postimg.cc/JhG5Z8V8/1000323583-removebg-preview.png"

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
        if request.method == "OPTIONS":
            return "", 200
        password = request.headers.get("X-Admin-Password")
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
    
    cur.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_pic TEXT DEFAULT '{DEFAULT_AVATAR}';")
    
    cur.execute("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1")
    if not cur.fetchone():
        admin_pass = generate_password_hash('admin')
        cur.execute("""
            INSERT INTO users (full_name, username, email, password, role)
            VALUES (%s, %s, %s, %s, %s)
        """, ('Admin', 'admin', 'admin@example.com', admin_pass, 'admin'))

    cur.execute("""
        CREATE TABLE IF NOT EXISTS results (
            result_id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            score INT NOT NULL,
            total_questions INT NOT NULL,
            submitted_at TIMESTAMP DEFAULT NOW()
        );
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS friend_requests (
            request_id SERIAL PRIMARY KEY,
            from_user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            to_user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(from_user_id, to_user_id)
        );
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS friends (
            friend_id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            friend_user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(user_id, friend_user_id)
        );
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            notif_id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'system',
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    
    cur.execute(f"ALTER TABLE notifications ADD COLUMN IF NOT EXISTS question_context TEXT;")
    cur.execute(f"ALTER TABLE notifications ADD COLUMN IF NOT EXISTS question_id INT;")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS question_comments (
            comment_id SERIAL PRIMARY KEY,
            question_id INT NOT NULL,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            comment_text TEXT NOT NULL,
            parent_comment_id INT REFERENCES question_comments(comment_id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    
    cur.execute(f"ALTER TABLE question_comments ADD COLUMN IF NOT EXISTS question_context TEXT;")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS comment_reactions (
            reaction_id SERIAL PRIMARY KEY,
            comment_id INT REFERENCES question_comments(comment_id) ON DELETE CASCADE,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            reaction_type TEXT CHECK (reaction_type IN ('like', 'dislike')),
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(comment_id, user_id)
        );
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS question_reports (
            report_id SERIAL PRIMARY KEY,
            question_id INT NOT NULL,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            reason TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    
    cur.execute(f"ALTER TABLE question_reports ADD COLUMN IF NOT EXISTS question_context TEXT;")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_notes (
            note_id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            title TEXT,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS saved_questions (
            save_id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
            question_id INT NOT NULL,
            question_text TEXT NOT NULL,
            subject TEXT,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(user_id, question_id)
        );
    """)
    
    conn.commit()
    cur.close()
    conn.close()

init_db()

# ================= LOGIN / REGISTER SYSTEM =================
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
        """, (data["full_name"], data["username"], data["email"].strip().lower(), generate_password_hash(data["password"]), 'user'))
        user = cur.fetchone()
        conn.commit()
        cur.close(); conn.close()
        return jsonify({"message": "Account created successfully", "user_id": user["user_id"]}), 201
    except IntegrityError as e:
        err = str(e).lower()
        if "username" in err: return jsonify({"error": "Username already exists"}), 400
        if "email" in err: return jsonify({"error": "Email already exists"}), 400
        return jsonify({"error": "Duplicate entry"}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    login_field = data.get("login")
    password = data.get("password")
    if not login_field or not password:
        return jsonify({"error": "Missing credentials"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (login_field, login_field))
    user = cur.fetchone()
    cur.close(); conn.close()
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401
    user.pop("password", None)
    return jsonify({"message": "Login successful", "user": user}), 200

# ================= ADMIN MANAGEMENT SYSTEM =================
@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    if data.get("username") != ADMIN_USERNAME or not check_password_hash(ADMIN_PASSWORD_HASH, data.get("password", "")):
        return jsonify({"error": "Invalid admin credentials"}), 401
    return jsonify({"message": "Login successful"}), 200

@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT user_id, full_name, username, email, role, created_at, profile_pic FROM users ORDER BY user_id DESC")
    users = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(users), 200

@app.route("/admin/users/<int:user_id>/password", methods=["PUT"])
@admin_required
def admin_reset_user_password(user_id):
    data = request.get_json() or {}
    if not data.get("password"): return jsonify({"error": "Password required"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (generate_password_hash(data["password"]), user_id))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message": "Password updated successfully"}), 200

@app.route("/admin/users/<int:user_id>/email", methods=["PUT"])
@admin_required
def admin_reset_user_email(user_id):
    data = request.get_json() or {}
    new_email = data.get("email")
    if not new_email: return jsonify({"error": "Email required"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET email=%s WHERE user_id=%s", (new_email, user_id))
        conn.commit()
        return jsonify({"message": "Email updated successfully"}), 200
    except IntegrityError: return jsonify({"error": "Email already in use"}), 400
    finally: cur.close(); conn.close()

@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE user_id=%s AND role='user'", (user_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"message": "User deleted successfully"}), 200

@app.route("/admin/reports", methods=["GET"])
@admin_required
def admin_list_reports():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT r.report_id, r.question_id, r.reason, r.question_context, r.created_at, u.user_id, u.username, u.email 
        FROM question_reports r 
        JOIN users u ON r.user_id = u.user_id 
        ORDER BY r.created_at DESC
    """)
    reports = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(reports), 200

@app.route("/admin/comments", methods=["GET"])
@admin_required
def admin_list_comments():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT c.comment_id, c.question_id, c.comment_text, c.question_context, c.parent_comment_id, c.created_at, u.user_id, u.username,
               (SELECT username FROM users u2 JOIN question_comments c2 ON u2.user_id = c2.user_id WHERE c2.comment_id = c.parent_comment_id) as replying_to
        FROM question_comments c 
        JOIN users u ON c.user_id = u.user_id 
        ORDER BY c.created_at DESC
    """)
    comments = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(comments), 200

@app.route("/admin/report/respond", methods=["POST"])
@admin_required
def admin_respond_report():
    data = request.get_json() or {}
    report_id = data.get("report_id")
    target_user_id = data.get("user_id")
    question_id = data.get("question_id")
    question_context = data.get("question_context", "")
    response_message = data.get("message", "").strip()

    if not all([report_id, target_user_id, question_id, response_message]):
        return jsonify({"error": "Missing validation tracking targets"}), 400

    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO notifications (user_id, title, message, type, question_id, question_context)
            VALUES (%s, %s, %s, 'report_reply', %s, %s)
        """, (target_user_id, "cbt.credit replied to your report", response_message, question_id, question_context))
        
        cur.execute("SELECT email, full_name FROM users WHERE user_id = %s", (target_user_id,))
        user_record = cur.fetchone()
        cur.execute("DELETE FROM question_reports WHERE report_id = %s", (report_id,))
        conn.commit()

        if user_record and user_record.get("email"):
            email_body = f"Hello {user_record['full_name']},\n\ncbt.credit reviewed your question report.\n\nResolution details:\n{response_message}"
            send_email(user_record["email"], f"CBT Portal: Question Report #{question_id} Resolution", email_body)

        return jsonify({"message": "Report resolved successfully"}), 200
    finally:
        cur.close(); conn.close()

@app.route("/admin/comment/reply", methods=["POST"])
@admin_required
def admin_reply_comment():
    data = request.get_json() or {}
    parent_comment_id = data.get("parent_comment_id")
    question_id = data.get("question_id")
    question_context = data.get("question_context", "")
    target_user_id = data.get("user_id")
    reply_text = data.get("text", "").strip()

    if not all([parent_comment_id, question_id, target_user_id, reply_text]):
        return jsonify({"error": "Missing input fields"}), 400

    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1")
        admin_user = cur.fetchone()
        admin_uid = admin_user["user_id"] if admin_user else 1

        cur.execute("""
            INSERT INTO question_comments (question_id, user_id, comment_text, parent_comment_id, question_context)
            VALUES (%s, %s, %s, %s, %s)
        """, (question_id, admin_uid, reply_text, parent_comment_id, question_context))

        cur.execute("""
            INSERT INTO notifications (user_id, title, message, type, question_id, question_context)
            VALUES (%s, %s, %s, 'comment_reply', %s, %s)
        """, (target_user_id, "cbt.credit replied to your comment", reply_text, question_id, question_context))
        
        cur.execute("SELECT email FROM users WHERE user_id = %s", (target_user_id,))
        user_record = cur.fetchone()
        conn.commit()

        if user_record and user_record.get("email"):
            send_email(user_record["email"], "CBT Portal: New cbt.credit Reply", f"An administrator replied to your comment: {reply_text}")

        return jsonify({"message": "Reply delivered successfully"}), 201
    finally:
        cur.close(); conn.close()

# ================= USER CORE API DATA ACCESS HOOKS =================
@app.route("/question/report", methods=["POST"])
def report_question():
    data = request.get_json() or {}
    qid = data.get("question_id")
    uid = data.get("user_id")
    reason = data.get("reason", "").strip()
    q_context = data.get("question_context", "")
    
    if not all([qid, uid, reason]): return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO question_reports (question_id, user_id, reason, question_context) 
            VALUES (%s,%s,%s,%s)
        """, (qid, uid, reason, q_context))
        conn.commit()
        return jsonify({"message": "Report submitted"}), 201
    finally: cur.close(); conn.close()

@app.route("/question/comments/<int:question_id>", methods=["GET"])
def get_comments(question_id):
    user_id = request.args.get("user_id", type=int)
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            SELECT c.*, u.username, u.profile_pic,
                   (SELECT COUNT(*) FROM comment_reactions WHERE comment_id=c.comment_id AND reaction_type='like') as likes,
                   (SELECT COUNT(*) FROM comment_reactions WHERE comment_id=c.comment_id AND reaction_type='dislike') as dislikes,
                   (SELECT reaction_type FROM comment_reactions WHERE comment_id=c.comment_id AND user_id=%s) as user_reaction
            FROM question_comments c JOIN users u ON c.user_id = u.user_id 
            WHERE c.question_id=%s ORDER BY c.created_at ASC
        """, (user_id, question_id))
        return jsonify(cur.fetchall()), 200
    finally: cur.close(); conn.close()

@app.route("/question/comment", methods=["POST", "OPTIONS"])
def post_comment():
    if request.method == "OPTIONS": return '', 200
    data = request.get_json(silent=True) or {}
    qid, uid, text, pid = data.get("question_id"), data.get("user_id"), data.get("text", "").strip(), data.get("parent_comment_id")
    q_context = data.get("question_context", "")

    if not qid or not uid or not text: return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO question_comments (question_id, user_id, comment_text, parent_comment_id, question_context) 
            VALUES (%s, %s, %s, %s, %s) RETURNING comment_id
        """, (qid, uid, text, pid, q_context))
        cid = cur.fetchone()["comment_id"]
        conn.commit()
        return jsonify({"message": "Posted", "comment_id": cid}), 201
    finally: cur.close(); conn.close()

@app.route("/comment/react", methods=["POST"])
def react_comment():
    data = request.get_json() or {}
    cid = data.get("comment_id")
    uid = data.get("user_id")
    rtype = data.get("type")
    if not cid or not uid or not rtype: return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO comment_reactions (comment_id, user_id, reaction_type)
            VALUES (%s, %s, %s)
            ON CONFLICT (comment_id, user_id) DO UPDATE SET reaction_type = %s
        """, (cid, uid, rtype, rtype))
        conn.commit()
        return jsonify({"message": "Reaction saved"}), 200
    finally: cur.close(); conn.close()

@app.route("/notifications/<int:user_id>", methods=["GET"])
def get_notifications(user_id):
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            SELECT notif_id, user_id, title, message, type, is_read, created_at, question_id, question_context 
            FROM notifications WHERE user_id=%s ORDER BY created_at DESC LIMIT 50
        """, (user_id,))
        return jsonify(cur.fetchall()), 200
    finally: cur.close(); conn.close()

@app.route("/history/save", methods=["POST"])
def save_history():
    data = request.get_json() or {}
    uid, score, total = data.get("user_id"), data.get("score"), data.get("total_questions")
    if uid is None or score is None or total is None: return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO results (user_id, score, total_questions) VALUES (%s, %s, %s) RETURNING result_id", (uid, score, total))
        res_id = cur.fetchone()["result_id"]; conn.commit()
        return jsonify({"message": "History saved", "result_id": res_id}), 201
    finally: cur.close(); conn.close()

@app.route("/history/<int:user_id>", methods=["GET"])
def get_history(user_id):
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT result_id, score, total_questions, submitted_at FROM results WHERE user_id=%s ORDER BY submitted_at DESC", (user_id,))
        return jsonify(cur.fetchall()), 200
    finally: cur.close(); conn.close()

@app.route("/")
def home(): return jsonify({"message": "CBT API Running"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)