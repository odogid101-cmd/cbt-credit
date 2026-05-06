import os
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from psycopg2 import connect
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# --- IMPORTANT: Session + CORS config for Render ---
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-this-in-production')
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Allow cross-site cookie
app.config['SESSION_COOKIE_SECURE'] = True      # Must be True for HTTPS on Render
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours

CORS(app, supports_credentials=True, origins=["*"])  # Replace "*" with your frontend URL in production

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db():
    return connect(DATABASE_URL, cursor_factory=RealDictCursor)

def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(200) UNIQUE NOT NULL,
                    password_hash VARCHAR(300) NOT NULL,
                    role VARCHAR(20) DEFAULT 'user' NOT NULL CHECK (role IN ('user', 'admin')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
            if not cur.fetchone():
                admin_pass = generate_password_hash('admin123')
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, role) 
                    VALUES (%s, %s, %s, %s)
                """, ('admin', 'admin@example.com', admin_pass, 'admin'))
                print("Default admin created: admin@example.com / admin123")
            
            # CBT tables
            cur.execute("""
                CREATE TABLE IF NOT EXISTS questions (
                    id SERIAL PRIMARY KEY,
                    question_text TEXT NOT NULL,
                    option_a VARCHAR(255) NOT NULL,
                    option_b VARCHAR(255) NOT NULL,
                    option_c VARCHAR(255) NOT NULL,
                    option_d VARCHAR(255) NOT NULL,
                    correct_answer CHAR(1) NOT NULL CHECK (correct_answer IN ('A','B','C','D')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    score INTEGER NOT NULL,
                    total_questions INTEGER NOT NULL,
                    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

init_db()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'You must be logged in'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# ---------- AUTH ROUTES ----------
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password are required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    password_hash = generate_password_hash(password)
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, role) 
                    VALUES (%s, %s, %s, %s) RETURNING id, username, email, role, created_at
                """, (username, email, password_hash, 'user'))
                user = cur.fetchone()
                conn.commit()
                return jsonify({'message': 'User registered successfully', 'user': user}), 201
    except Exception:
        return jsonify({'error': 'Username or email already exists'}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['username'] = user['username']
        session.permanent = True  # Make session last 24h
        return jsonify({
            'message': 'Login successful', 
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email'], 'role': user['role']}
        }), 200
    
    return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/me', methods=['GET'])
@login_required
def me():
    user_id = session.get('user_id')
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, email, role, created_at FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
    return jsonify({'user': user}), 200

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

# ---------- ADMIN ROUTES ----------
@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC")
            users = cur.fetchall()
    return jsonify({'users': users, 'count': len(users)}), 200

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'error': 'You cannot delete your own account'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s RETURNING id, username", (user_id,))
            deleted = cur.fetchone()
            conn.commit()
    if not deleted:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'message': f"User {deleted['username']} deleted successfully"}), 200

@app.route('/admin/users/<int:user_id>/role', methods=['PUT'])
@admin_required
def admin_update_role(user_id):
    data = request.get_json()
    new_role = data.get('role')
    if new_role not in ['user', 'admin']:
        return jsonify({'error': 'Role must be either user or admin'}), 400
    if user_id == session.get('user_id'):
        return jsonify({'error': 'You cannot change your own role'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET role = %s WHERE id = %s RETURNING id, username, role", (new_role, user_id))
            updated = cur.fetchone()
            conn.commit()
    if not updated:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'message': 'Role updated successfully', 'user': updated}), 200

# ---------- CBT ROUTES ----------
@app.route('/admin/questions', methods=['POST'])
@admin_required
def add_question():
    data = request.get_json()
    required = ['question_text', 'option_a', 'option_b', 'option_c', 'option_d', 'correct_answer']
    if not all(data.get(k) for k in required):
        return jsonify({'error': 'All fields are required'}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO questions (question_text, option_a, option_b, option_c, option_d, correct_answer)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (data['question_text'], data['option_a'], data['option_b'], data['option_c'], 
                  data['option_d'], data['correct_answer'].upper()))
            q = cur.fetchone()
            conn.commit()
    return jsonify({'message': 'Question added successfully', 'id': q['id']}), 201

@app.route('/questions', methods=['GET'])
@login_required
def get_questions():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, question_text, option_a, option_b, option_c, option_d FROM questions ORDER BY RANDOM() LIMIT 20")
            questions = cur.fetchall()
    return jsonify({'questions': questions}), 200

@app.route('/submit-exam', methods=['POST'])
@login_required
def submit_exam():
    data = request.get_json()
    answers = data.get('answers', {})
    user_id = session.get('user_id')
    if not answers:
        return jsonify({'error': 'No answers submitted'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            q_ids = list(answers.keys())
            cur.execute(f"SELECT id, correct_answer FROM questions WHERE id IN ({','.join(['%s']*len(q_ids))})", q_ids)
            correct_answers = {str(row['id']): row['correct_answer'] for row in cur.fetchall()}
            score = sum(1 for qid, ans in answers.items() if correct_answers.get(qid) == ans.upper())
            total = len(correct_answers)
            cur.execute("INSERT INTO results (user_id, score, total_questions) VALUES (%s, %s, %s) RETURNING id", 
                        (user_id, score, total))
            conn.commit()
    percentage = round((score / total) * 100, 2) if total > 0 else 0
    return jsonify({'message': 'Exam submitted', 'score': score, 'total': total, 'percentage': percentage}), 200

@app.route('/admin/results', methods=['GET'])
@admin_required
def admin_get_results():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT r.id, u.username, u.email, r.score, r.total_questions, 
                       ROUND((r.score::FLOAT / r.total_questions) * 100, 2) as percentage, r.submitted_at
                FROM results r JOIN users u ON r.user_id = u.id ORDER BY r.submitted_at DESC
            """)
            results = cur.fetchall()
    return jsonify({'results': results}), 200

@app.route('/')
def home():
    return jsonify({'message': 'Flask CBT API Running'})

if __name__ == '__main__':
    app.run(debug=True)
