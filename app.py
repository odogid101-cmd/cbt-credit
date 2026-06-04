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
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "cbtcredit.support@gmail.com")
DEFAULT_AVATAR = "https://i.postimg.cc/JhG5Z8V8/1000323583-removebg-preview.png"

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

if not SENDGRID_API_KEY:
    raise RuntimeError("SENDGRID_API_KEY not set")

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

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

# ================= AUTH ROUTES =================
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    full_name = data.get("full_name")
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    
    if not all([full_name, username, email, password]):
        return jsonify({"error": "All fields required"}), 400
    
    hashed_pw = generate_password_hash(password)
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (full_name, username, email, password) 
            VALUES (%s, %s, %s, %s) RETURNING user_id
        """, (full_name, username, email, hashed_pw))
        user_id = cur.fetchone()["user_id"]
        conn.commit()
        return jsonify({"message": "Registered", "user_id": user_id}), 201
    except IntegrityError:
        return jsonify({"error": "Username or email exists"}), 400
    finally: cur.close(); conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    
    if not all([email, password]):
        return jsonify({"error": "Email and password required"}), 400
    
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401
        
        return jsonify({
            "message": "Login successful",
            "user_id": user["user_id"],
            "full_name": user["full_name"],
            "username": user["username"],
            "email": user["email"],
            "profile_pic": user.get("profile_pic") or DEFAULT_AVATAR
        }), 200
    finally: cur.close(); conn.close()

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json() or {}
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email required"}), 400
    
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        if not user:
            return jsonify({"error": "Email not found"}), 404
        
        code = ''.join(secrets.choice('0123456789') for _ in range(6))
        expiry = datetime.now() + timedelta(minutes=10)
        cur.execute("UPDATE users SET reset_code=%s, reset_code_expiry=%s WHERE email=%s", (code, expiry, email))
        conn.commit()
        
        send_email(email, "CBT Credit - Password Reset Code", f"Your reset code is: {code}\nThis code expires in 10 minutes.")
        return jsonify({"message": "Reset code sent"}), 200
    finally: cur.close(); conn.close()

@app.route("/verify-reset-code", methods=["POST"])
def verify_reset_code():
    data = request.get_json() or {}
    email = data.get("email")
    code = data.get("code")
    
    if not all([email, code]):
        return jsonify({"error": "Email and code required"}), 400
    
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT reset_code, reset_code_expiry FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        if not user or user["reset_code"] != code:
            return jsonify({"error": "Invalid code"}), 400
        if user["reset_code_expiry"] < datetime.now():
            return jsonify({"error": "Code expired"}), 400
        return jsonify({"message": "Code verified"}), 200
    finally: cur.close(); conn.close()

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}
    email = data.get("email")
    code = data.get("code")
    new_password = data.get("new_password")
    
    if not all([email, code, new_password]):
        return jsonify({"error": "All fields required"}), 400
    
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT reset_code, reset_code_expiry FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        if not user or user["reset_code"] != code:
            return jsonify({"error": "Invalid code"}), 400
        if user["reset_code_expiry"] < datetime.now():
            return jsonify({"error": "Code expired"}), 400
        
        hashed_pw = generate_password_hash(new_password)
        cur.execute("UPDATE users SET password=%s, reset_code=NULL, reset_code_expiry=NULL WHERE email=%s", (hashed_pw, email))
        conn.commit()
        return jsonify({"message": "Password reset successful"}), 200
    finally: cur.close(); conn.close()

# ================= ADMIN ROUTES =================
@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_get_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_id, full_name, username, email, role, created_at FROM users WHERE role='user' ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(users), 200

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

# ================= PROFILE =================
@app.route("/profile/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute(f"""
            SELECT user_id, full_name, username, email, 
                   COALESCE(profile_pic, '{DEFAULT_AVATAR}') as profile_pic, 
                   created_at FROM users WHERE user_id=%s
        """, (user_id,))
        user = cur.fetchone()
        if not user: return jsonify({"error": "User not found"}), 404
        return jsonify(user), 200
    finally: cur.close(); conn.close()

@app.route("/profile/update", methods=["PUT"])
def update_profile():
    data = request.get_json() or {}
    user_id, full_name, username = data.get("user_id"), data.get("full_name","").strip(), data.get("username","").strip()
    if not all([user_id, full_name, username]): return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET full_name=%s, username=%s WHERE user_id=%s", (full_name, username, user_id))
        if cur.rowcount == 0: return jsonify({"error": "User not found"}), 404
        conn.commit(); return jsonify({"message": "Profile updated"}), 200
    except IntegrityError: return jsonify({"error": "Username taken"}), 400
    finally: cur.close(); conn.close()

@app.route("/profile/change-email", methods=["PUT"])
def profile_change_email():
    data = request.get_json() or {}
    user_id, new_email, password = data.get("user_id"), data.get("email","").strip().lower(), data.get("password")
    if not all([user_id, new_email, password]): return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT password FROM users WHERE user_id=%s", (user_id,))
        user = cur.fetchone()
        if not user or not check_password_hash(user["password"], password): return jsonify({"error": "Invalid password"}), 401
        cur.execute("UPDATE users SET email=%s WHERE user_id=%s", (new_email, user_id))
        conn.commit(); return jsonify({"message": "Email updated"}), 200
    except IntegrityError: return jsonify({"error": "Email in use"}), 400
    finally: cur.close(); conn.close()

@app.route("/profile/change-password", methods=["PUT"])
def profile_change_password():
    data = request.get_json() or {}
    user_id, old_pw, new_pw = data.get("user_id"), data.get("old_password"), data.get("new_password")
    if not all([user_id, old_pw, new_pw]): return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT password FROM users WHERE user_id=%s", (user_id,))
        user = cur.fetchone()
        if not user or not check_password_hash(user["password"], old_pw): return jsonify({"error": "Invalid old password"}), 401
        cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (generate_password_hash(new_pw), user_id))
        conn.commit(); return jsonify({"message": "Password updated"}), 200
    finally: cur.close(); conn.close()

@app.route("/profile/pic", methods=["PUT"])
def update_profile_pic():
    data = request.get_json() or {}
    user_id, pic_url = data.get("user_id"), data.get("profile_pic")
    if not user_id or not pic_url: return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET profile_pic=%s WHERE user_id=%s", (pic_url, user_id))
        conn.commit(); return jsonify({"message": "Profile pic updated"}), 200
    finally: cur.close(); conn.close()
# ================= FRIENDS =================
@app.route("/friends/request", methods=["POST"])
def send_friend_request():
    data = request.get_json() or {}
    from_id, to_id = data.get("from_user_id"), data.get("to_user_id")
    if not from_id or not to_id or from_id == to_id: return jsonify({"error": "Invalid"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO friend_requests (from_user_id, to_user_id) VALUES (%s, %s)", (from_id, to_id))
        conn.commit(); return jsonify({"message": "Request sent"}), 201
    except IntegrityError: return jsonify({"error": "Request exists"}), 400
    finally: cur.close(); conn.close()

@app.route("/friends/accept/<int:request_id>", methods=["POST"])
def accept_friend_request(request_id):
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT from_user_id, to_user_id FROM friend_requests WHERE request_id=%s AND status='pending'", (request_id,))
        req = cur.fetchone()
        if not req: return jsonify({"error": "Request not found"}), 404
        cur.execute("UPDATE friend_requests SET status='accepted' WHERE request_id=%s", (request_id,))
        cur.execute("INSERT INTO friends (user_id, friend_user_id) VALUES (%s, %s)", (req["from_user_id"], req["to_user_id"]))
        cur.execute("INSERT INTO friends (user_id, friend_user_id) VALUES (%s, %s)", (req["to_user_id"], req["from_user_id"]))
        conn.commit(); return jsonify({"message": "Friend added"}), 200
    finally: cur.close(); conn.close()

@app.route("/friends/list/<int:user_id>", methods=["GET"])
def list_friends(user_id):
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            SELECT u.user_id, u.full_name, u.username, u.profile_pic 
            FROM friends f JOIN users u ON f.friend_user_id = u.user_id WHERE f.user_id=%s
        """, (user_id,))
        return jsonify(cur.fetchall()), 200
    finally: cur.close(); conn.close()

# ================= HELPER: GET OR CREATE QUESTION - FIXED FOR RACE CONDITION =================
def get_or_create_question_id(question_text, subject, exam):
    question_text = question_text[:1000] if question_text else ''
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO questions (exam, subject, question_text, option_a, option_b, option_c, option_d, correct_answer)
            VALUES (%s, %s, %s, '', '', '', '', 'A')
            ON CONFLICT (question_text, subject, exam) DO UPDATE SET 
                exam = EXCLUDED.exam
            RETURNING question_id
        """, (exam, subject, question_text))
        qid = cur.fetchone()["question_id"]
        conn.commit()
        return qid
    except Exception as e:
        print(f"get_or_create_question_id error: {e}")
        conn.rollback()
        cur.execute("""
            SELECT question_id FROM questions
            WHERE question_text=%s AND subject=%s AND exam=%s
        """, (question_text, subject, exam))
        row = cur.fetchone()
        if row:
            return row["question_id"]
        raise
    finally:
        cur.close()
        conn.close()

# ================= COMMENTS + REACTIONS =================
@app.route("/question/comments/<int:question_id>", methods=["GET"])
def get_comments(question_id):
    user_id = request.args.get("user_id", type=int)
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            SELECT c.*, u.username, COALESCE(u.profile_pic, %s) as profile_pic,
                   (SELECT COUNT(*) FROM comment_reactions WHERE comment_id=c.comment_id AND reaction_type='like') as likes,
                   (SELECT COUNT(*) FROM comment_reactions WHERE comment_id=c.comment_id AND reaction_type='dislike') as dislikes,
                   (SELECT reaction_type FROM comment_reactions WHERE comment_id=c.comment_id AND user_id=%s) as user_reaction
            FROM question_comments c JOIN users u ON c.user_id = u.user_id 
            WHERE c.question_id=%s ORDER BY c.created_at ASC
        """, (DEFAULT_AVATAR, user_id, question_id))
        return jsonify(cur.fetchall()), 200
    except Exception as e:
        print(f"Get comments error: {e}")
        return jsonify({"error": str(e)}), 500
    finally: cur.close(); conn.close()

@app.route("/question/comment", methods=["POST"])
def post_comment():
    data = request.get_json() or {}
    qid = data.get("question_id")
    uid = data.get("user_id")
    text = data.get("text","").strip()
    pid = data.get("parent_comment_id")
    q_text = data.get("question_text")
    q_subject = data.get("subject")
    q_exam = data.get("exam")

    if not all([uid, text]):
        return jsonify({"error": "Missing fields"}), 400

    if not qid and q_text and q_subject and q_exam:
        qid = get_or_create_question_id(q_text, q_subject, q_exam)

    if not qid:
        return jsonify({"error": "Question ID required"}), 400

    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO question_comments (question_id, user_id, comment_text, parent_comment_id)
            VALUES (%s,%s,%s,%s) RETURNING comment_id
        """, (qid, uid, text, pid))
        cid = cur.fetchone()["comment_id"]; conn.commit()
        return jsonify({"message": "Posted", "comment_id": cid, "question_id": qid}), 201
    except Exception as e:
        print(f"Post comment error: {e}")
        return jsonify({"error": str(e)}), 500
    finally: cur.close(); conn.close()

@app.route("/comment/react", methods=["POST"])
def react_comment():
    data = request.get_json() or {}
    cid, uid, rtype = data.get("comment_id"), data.get("user_id"), data.get("type")
    if not all([cid, uid, rtype]): return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT reaction_type FROM comment_reactions WHERE comment_id=%s AND user_id=%s", (cid, uid))
        existing = cur.fetchone()
        if existing:
            if existing["reaction_type"] == rtype:
                cur.execute("DELETE FROM comment_reactions WHERE comment_id=%s AND user_id=%s", (cid, uid))
            else:
                cur.execute("UPDATE comment_reactions SET reaction_type=%s WHERE comment_id=%s AND user_id=%s", (rtype, cid, uid))
        else:
            cur.execute("INSERT INTO comment_reactions (comment_id, user_id, reaction_type) VALUES (%s,%s,%s)", (cid, uid, rtype))
        conn.commit(); return jsonify({"message": "Reaction updated"}), 200
    finally: cur.close(); conn.close()

# ================= REPORTS + NOTES + HISTORY =================
@app.route("/question/report", methods=["POST"])
def report_question():
    data = request.get_json() or {}
    qid = data.get("question_id")
    uid = data.get("user_id")
    reason = data.get("reason","").strip()
    q_text = data.get("question_text")
    q_subject = data.get("subject")
    q_exam = data.get("exam")

    if not all([uid, reason]):
        return jsonify({"error": "Missing fields"}), 400

    if not qid and q_text and q_subject and q_exam:
        qid = get_or_create_question_id(q_text, q_subject, q_exam)

    if not qid:
        return jsonify({"error": "Question ID required"}), 400

    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO question_reports (question_id, user_id, reason) VALUES (%s,%s,%s)", (qid, uid, reason))
        conn.commit(); 
        return jsonify({"message": "Report submitted", "question_id": qid}), 201
    except Exception as e:
        print(f"Report error: {e}")
        return jsonify({"error": str(e)}), 500
    finally: cur.close(); conn.close()

@app.route("/history/<int:user_id>", methods=["GET"])
def get_history(user_id):
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT result_id, score, total_questions, submitted_at FROM results WHERE user_id=%s ORDER BY submitted_at DESC", (user_id,))
        return jsonify(cur.fetchall()), 200
    finally: cur.close(); conn.close()

@app.route("/history/save", methods=["POST"])
def save_history():
    data = request.get_json() or {}
    uid = data.get("user_id")
    score = data.get("score")
    total = data.get("total_questions")
    
    if not all([uid, score is not None, total]):
        return jsonify({"error": "Missing fields"}), 400
    
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO results (user_id, score, total_questions) 
            VALUES (%s, %s, %s)
        """, (uid, score, total))
        conn.commit()
        return jsonify({"message": "History saved"}), 201
    finally: cur.close(); conn.close()

@app.route("/notes", methods=["POST"])
def create_note():
    data = request.get_json() or {}
    uid, title, content = data.get("user_id"), data.get("title","").strip(), data.get("content","").strip()
    if not uid or not content: return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO user_notes (user_id, title, content) VALUES (%s,%s,%s) RETURNING note_id", (uid, title, content))
        nid = cur.fetchone()["note_id"]; conn.commit()
        return jsonify({"message": "Note saved", "note_id": nid}), 201
    finally: cur.close(); conn.close()

@app.route("/notes/<int:user_id>", methods=["GET"])
def get_notes(user_id):
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM user_notes WHERE user_id=%s ORDER BY created_at DESC", (user_id,))
        return jsonify(cur.fetchall()), 200
    finally: cur.close(); conn.close()

@app.route("/notifications/<int:user_id>", methods=["GET"])
def get_notifications(user_id):
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM notifications WHERE user_id=%s ORDER BY created_at DESC LIMIT 50", (user_id,))
        return jsonify(cur.fetchall()), 200
    finally: cur.close(); conn.close()

# ================= ROOT =================
@app.route("/")
def home():
    return jsonify({"message": "CBT API Running"})

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
