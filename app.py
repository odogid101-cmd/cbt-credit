
import os
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from psycopg2 import connect
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
CORS(app, supports_credentials=True)  # needed for session cookies
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-this-in-production')

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db():
    return connect(DATABASE_URL, cursor_factory=RealDictCursor)

def init_db():
    """Create users table and default admin if they don't exist."""
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
            # Create default admin if none exists
            cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
            if not cur.fetchone():
                admin_pass = generate_password_hash('admin123')
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, role) 
                    VALUES (%s, %s, %s, %s)
                """, ('admin', 'admin@example.com', admin_pass, 'admin'))
                print("Default admin created: admin@example.com / admin123")
            conn.commit()

init_db()

# Decorator to protect routes
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

# ---------- USER ROUTES ----------

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
                    VALUES (%s, %s, %s, %s) 
                    RETURNING id, username, email, role, created_at
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

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['username'] = user['username']
        return jsonify({
            'message': 'Login successful', 
            'user': {'id': user['id'], 'username': user['username'], 'email': user['email'], 'role': user['role']}
        }), 200
    
    return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/me', methods=['GET'])
@login_required
def me():
    """Get current logged-in user profile"""
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
    """Admin: View all users"""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC")
            users = cur.fetchall()
    return jsonify({'users': users, 'count': len(users)}), 200

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    """Admin: Delete a user by ID. Cannot delete yourself."""
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
    """Admin: Update user role to 'admin' or 'user'"""
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

@app.route('/')
def home():
    return jsonify({
        'message': 'Flask Auth API Running',
        'endpoints': {
            'POST /register': 'Create new user account',
            'POST /login': 'Login user or admin',
            'GET /me': 'Get current user profile [Auth required]',
            'POST /logout': 'Logout [Auth required]',
            'GET /admin/users': 'List all users [Admin only]',
            'DELETE /admin/users/<id>': 'Delete user [Admin only]',
            'PUT /admin/users/<id>/role': 'Update user role [Admin only]'
        }
    })

if __name__ == '__main__':
    app.run(debug=True)            
