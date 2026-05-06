import os
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from psycopg2 import connect, sql
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-this')

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db():
    return connect(DATABASE_URL, cursor_factory=RealDictCursor)

def init_db():
    """Create users table if it doesn't exist. Run once on startup."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(200) UNIQUE NOT NULL,
                    password_hash VARCHAR(300) NOT NULL,
                    role VARCHAR(20) DEFAULT 'user' NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            # Create default admin if none exists
            cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
            if not cur.fetchone():
                admin_pass = generate_password_hash('admin123')
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, role) 
                    VALUES (%s, %s, %s, %s)
                """, ('admin', 'admin@example.com', admin_pass, 'admin'))
            conn.commit()

init_db()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password are required'}), 400

    password_hash = generate_password_hash(password)

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, role) 
                    VALUES (%s, %s, %s, %s) RETURNING id, username, email, role
                """, (username, email, password_hash, 'user'))
                user = cur.fetchone()
                conn.commit()
                return jsonify({'message': 'User registered successfully', 'user': user}), 201
    except Exception as e:
        return jsonify({'error': 'Username or email already exists'}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['role'] = user['role']
        return jsonify({
            'message': 'Login successful', 
            'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}
        }), 200
    
    return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/admin/users', methods=['GET'])
def admin_users():
    # Simple admin check
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized. Admin access only'}), 403

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC")
            users = cur.fetchall()
    return jsonify({'users': users}), 200

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/me', methods=['GET'])
def me():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, email, role FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
    return jsonify({'user': user}), 200

@app.route('/')
def home():
    return jsonify({'message': 'Flask Auth API is running. Endpoints: /register, /login, /admin/users, /me'})

if __name__ == '__main__':
    app.run(debug=True)