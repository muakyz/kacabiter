from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta
from functools import wraps
from sql import get_connection
import logging

load_dotenv()

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)

JWT_SECRET = os.getenv('JWT_SECRET', 'your_jwt_secret_key')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
JWT_EXP_DELTA_SECONDS = int(os.getenv('JWT_EXP_DELTA_SECONDS', 3600))

conn = get_connection()
cursor = conn.cursor()

import jwt
from datetime import datetime, timedelta, timezone

def generate_jwt(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.now(timezone.utc) + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    return jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user_id = data['user_id']
            current_username = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user_id, current_username, *args, **kwargs)

    return decorated_function

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required.'}), 400

    try:
        cursor = get_connection().cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return jsonify({'message': 'Username already exists.'}), 409

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        insert_query = """
            INSERT INTO users (username, password)
            VALUES (?, ?)
        """
        cursor.execute(insert_query, (username, hashed_password))
        cursor.connection.commit()

        return jsonify({'message': 'User registered successfully.'}), 200
    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({'message': 'Registration failed.'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required.'}), 400

    try:
        cursor = get_connection().cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return jsonify({'message': 'Invalid username or password.'}), 400

        token = generate_jwt(user.user_id, user.username)
        return jsonify({'message': 'Login successful', 'token': token}), 200
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({'message': 'Login failed.'}), 500

@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user_id, current_username):
    return jsonify({'message': f'Welcome {current_username}!', 'user_id': current_user_id}), 200

if __name__ == '__main__':
    PORT = 8000
    app.run(host='0.0.0.0', port=PORT, debug=True)
