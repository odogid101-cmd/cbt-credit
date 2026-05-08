import os
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

# ================= ADMIN CONFIG =================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash("@9064_tech")

# ================= APP =================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

# ================= DB CONNECTION =================
def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor, sslmode="require")

# ================= ADMIN GUARD =================
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        data = request.get_json(silent=True) or {}
        password = data.get("admin_password")
        if not password or not check_password_hash(ADMIN_PASSWORD_HASH, password):
            return jsonify({"error": "Admin authorization required"}), 403
        return f(*args, **kwargs)
    return wrapper

# ================= INIT DB =================
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # 1. USERS - create table first before checking for admin
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            full_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()

    # 2. Create default admin if none exists
    cur.execute("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1")
    if not cur.fetchone():
        admin_pass = generate_password_hash('@9064_tech')
        cur.execute("""
            INSERT INTO users (full_name, username, email, password, role) 
            VALUES (%s, %s, %s, %s, %s)
        """, ('Admin', 'admin', 'admin@example.com', admin_pass, 'admin'))
        conn.commit()

    # 3. SUBJECTS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS subjects (
            subject_id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            exam_type TEXT NOT NULL DEFAULT 'JAMB',
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()

    cur.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.table_constraints
            WHERE table_name='subjects' AND constraint_name='unique_subject_per_exam_type'
        ) THEN
            ALTER TABLE subjects ADD CONSTRAINT unique_subject_per_exam_type UNIQUE(name, exam_type);
        END IF;
    END $$;
    """)
    conn.commit()

    # 4. TOPICS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS topics (
            topic_id SERIAL PRIMARY KEY,
            subject_id INT REFERENCES subjects(subject_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            explanation TEXT,
            jamb_percentage INT,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()

    # 5. QUESTIONS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS questions (
            question_id SERIAL PRIMARY KEY,
            subject_id INT REFERENCES subjects(subject_id) ON DELETE CASCADE,
            topic_id INT REFERENCES topics(topic_id) ON DELETE CASCADE,
            exam_type TEXT NOT NULL,
            question TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT NOT NULL,
            option_d TEXT NOT NULL,
            option_e TEXT,
            answer TEXT NOT NULL,
            explanation TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()

    # 6. RESULTS
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
    if data.get("username") != ADMIN_USERNAME:
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

# ================= SUBJECT ROUTES =================
@app.route("/admin/subjects", methods=["POST"])
@admin_required
def add_subject():
    data = request.get_json() or {}
    name = data.get("name")
    exam_type = data.get("exam_type")
    if not name or not exam_type:
        return jsonify({"error": "name and exam_type required"}), 400
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO subjects (name, exam_type) VALUES (%s,%s) RETURNING *", (name, exam_type))
        subject = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Subject added", "subject": subject}), 201
    except IntegrityError:
        return jsonify({"error": "Subject already exists for this exam type"}), 400

@app.route("/admin/subjects", methods=["GET"])
def get_subjects():
    exam_type = request.args.get("exam_type")
    conn = get_db_connection()
    cur = conn.cursor()
    if exam_type:
        cur.execute("SELECT * FROM subjects WHERE exam_type=%s ORDER BY subject_id DESC", (exam_type,))
    else:
        cur.execute("SELECT * FROM subjects ORDER BY subject_id DESC")
    subjects = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(subjects), 200

@app.route("/admin/subjects/<int:subject_id>", methods=["DELETE"])
@admin_required
def delete_subject(subject_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM subjects WHERE subject_id=%s RETURNING subject_id", (subject_id,))
    deleted = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    if not deleted:
        return jsonify({"error": "Subject not found"}), 404
    return jsonify({"message": "Subject deleted"}), 200

# ================= TOPICS =================
@app.route("/admin/topics", methods=["POST"])
@admin_required
def add_topic():
    data = request.get_json() or {}
    subject_id = data.get("subject_id")
    name = data.get("name")
    explanation = data.get("explanation")
    jamb_percentage = data.get("jamb_percentage")
    if not subject_id or not name:
        return jsonify({"error": "subject_id and name required"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO topics (subject_id, name, explanation, jamb_percentage)
        VALUES (%s,%s,%s,%s) RETURNING *;
    """, (subject_id, name, explanation, jamb_percentage))
    topic = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(topic), 201

@app.route("/admin/topics", methods=["GET"])
def get_topics():
    subject_id = request.args.get("subject_id")
    if not subject_id:
        return jsonify({"error": "subject_id required"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM topics WHERE subject_id=%s ORDER BY topic_id DESC", (subject_id,))
    topics = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(topics), 200

# ================= QUESTIONS =================
@app.route("/admin/questions", methods=["POST"])
@admin_required
def add_question():
    data = request.get_json() or {}
    required = ["subject_id", "topic_id", "exam_type", "question", "option_a", "option_b", "option_c", "option_d", "answer"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"{field} required"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO questions (
            subject_id, topic_id, exam_type, question, option_a, option_b, option_c, option_d, option_e, answer, explanation
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *;
    """, (
        data["subject_id"], data["topic_id"], data["exam_type"], data["question"],
        data["option_a"], data["option_b"], data["option_c"], data["option_d"],
        data.get("option_e"), data["answer"], data.get("explanation")
    ))
    question = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return jsonify(question), 201

@app.route("/questions", methods=["GET"])
def get_questions():
    subject_id = request.args.get("subject_id")
    topic_id = request.args.get("topic_id")
    exam_type = request.args.get("exam_type")
    conn = get_db_connection()
    cur = conn.cursor()
    query = "SELECT question_id, question, option_a, option_b, option_c, option_d, option_e FROM questions WHERE 1=1"
    params = []
    if subject_id:
        query += " AND subject_id=%s"; params.append(subject_id)
    if topic_id:
        query += " AND topic_id=%s"; params.append(topic_id)
    if exam_type:
        query += " AND exam_type=%s"; params.append(exam_type)
    query += " ORDER BY RANDOM() LIMIT 20"
    cur.execute(query, params)
    questions = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({'questions': questions}), 200

@app.route("/submit-exam", methods=["POST"])
def submit_exam():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    answers = data.get("answers", {})
    if not user_id or not answers:
        return jsonify({"error": "user_id and answers required"}), 400
    conn = get_db_connection()
    cur = conn.cursor()
    q_ids = list(answers.keys())
    if not q_ids:
        return jsonify({"error": "No answers provided"}), 400
    cur.execute(f"SELECT question_id, answer FROM questions WHERE question_id IN ({','.join(['%s']*len(q_ids))})", q_ids)
    correct_answers = {str(row['question_id']): str(row['answer']) for row in cur.fetchall()}
    score = sum(1 for qid, ans in answers.items() if correct_answers.get(str(qid)) == str(ans))
    total = len(correct_answers)
    cur.execute("INSERT INTO results (user_id, score, total_questions) VALUES (%s, %s, %s) RETURNING result_id", 
                (user_id, score, total))
    conn.commit()
    cur.close()
    conn.close()
    percentage = round((score / total) * 100, 2) if total > 0 else 0
    return jsonify({'score': score, 'total': total, 'percentage': percentage}), 200

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
    login_field = data.get("login")  # can be username or email
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

@app.route("/")
def home():
    return jsonify({"message": "CBT API Running"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
            
