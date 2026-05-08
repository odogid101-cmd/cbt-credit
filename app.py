from flask import Flask, request, jsonify
from flask_mail import Mail, Message
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import jwt
import os
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Config from env vars
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-to-something-random')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False') == 'True'
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)

FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')

def get_db_connection():
    conn = psycopg2.connect(os.environ['DATABASE_URL'], cursor_factory=RealDictCursor)
    return conn

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not all([full_name, email, password]):
        return jsonify({'error': 'All fields required'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (full_name, email, password_hash) VALUES (%s, %s, %s)",
            (full_name, email, hashed_password)
        )
        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({'error': 'Email already exists'}), 409
    finally:
        cur.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'error': 'Invalid email or password'}), 401

    return jsonify({'message': 'Login successful', 'user_id': user['id']}), 200

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    # Always return same message for security
    if not user:
        return jsonify({'message': 'If an account exists with this email, a reset link has been sent.'}), 200

    # Create JWT token valid for 1 hour
    payload = {
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    reset_link = f"{FRONTEND_URL}/reset-password.html?token={token}"

    try:
        msg = Message(
            subject='Password Reset Request',
            recipients=[email],
            body=f'Click the link to reset your password:\n{reset_link}\n\nThis link expires in 1 hour.'
        )
        mail.send(msg)
    except Exception as e:
        print(f"Email send error: {e}")
        return jsonify({'error': 'Failed to send email'}), 500

    return jsonify({'message': 'If an account exists with this email, a reset link has been sent.'}), 200

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('password')

    if not token or not new_password:
        return jsonify({'error': 'Token and password required'}), 400

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        email = payload['email']
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 400

    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_password, email))
    if cur.rowcount == 0:
        cur.close()
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'message': 'Password updated successfully'}), 200

@app.route('/')
def index():
    return "CBT Credit API is running"

if __name__ == '__main__':
    app.run(debug=True)
