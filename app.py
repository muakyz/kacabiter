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
from datetime import datetime, timedelta, timezone

load_dotenv()

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)

JWT_SECRET = os.getenv('JWT_SECRET', 'your_jwt_secret_key')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
JWT_EXP_DELTA_SECONDS = int(os.getenv('JWT_EXP_DELTA_SECONDS', 3600))

conn = get_connection()
cursor = conn.cursor()

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
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            return jsonify({'message': 'Invalid username or password.'}), 400

        token = generate_jwt(user[0], user[1])
        return jsonify({'message': 'Login successful', 'token': token}), 200
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({'message': 'Login failed.'}), 500

@app.route('/join_room/<int:room_id>', methods=['POST'])
@token_required
def join_room(current_user_id, current_username, room_id):
    try:
        cursor.execute("SELECT * FROM room_users WHERE room_id = ? AND user_id = ?", (room_id, current_user_id))
        if cursor.fetchone():
            return jsonify({'message': 'User already in the room.'}), 409

        cursor.execute("INSERT INTO room_users (room_id, user_id) VALUES (?, ?)", (room_id, current_user_id))
        cursor.connection.commit()

        return jsonify({'message': 'User joined the room successfully.'}), 200
    except Exception as e:
        logging.error(f"Error joining room: {e}")
        return jsonify({'message': 'Failed to join room.'}), 500

@app.route('/room_users/<int:room_id>', methods=['GET'])
def get_room_users(room_id):
    try:
        cursor.execute("""
            SELECT u.username 
            FROM users u
            INNER JOIN room_users ru ON u.user_id = ru.user_id
            WHERE ru.room_id = ?
        """, (room_id,))
        users = cursor.fetchall()
        return jsonify({'room_id': room_id, 'users': [user[0] for user in users]}), 200
    except Exception as e:
        logging.error(f"Error fetching room users: {e}")
        return jsonify({'message': 'Failed to fetch room users.'}), 500

@app.route('/submit_guess', methods=['POST'])
@token_required
def submit_guess(current_user_id, current_username):
    data = request.get_json()
    car_id = data.get('car_id')
    guessed_price = data.get('guessed_price')

    if not car_id or not guessed_price:
        return jsonify({'message': 'Car ID and guessed price are required.'}), 400

    try:
        cursor.execute("""
            INSERT INTO price_guesses (car_id, user_id, guessed_price)
            VALUES (?, ?, ?)
        """, (car_id, current_user_id, guessed_price))
        cursor.connection.commit()

        return jsonify({'message': 'Price guess submitted successfully.'}), 200
    except Exception as e:
        logging.error(f"Error submitting guess: {e}")
        return jsonify({'message': 'Failed to submit guess.'}), 500

@app.route('/price_guesses/<int:car_id>', methods=['GET'])
def get_price_guesses(car_id):
    try:
        cursor.execute("""
            SELECT u.username, pg.guessed_price
            FROM price_guesses pg
            INNER JOIN users u ON pg.user_id = u.user_id
            WHERE pg.car_id = ?
            ORDER BY ABS(pg.guessed_price - (SELECT price FROM cars WHERE car_id = ?))
        """, (car_id, car_id))
        guesses = cursor.fetchall()
        return jsonify({'car_id': car_id, 'guesses': [{'username': guess[0], 'guessed_price': guess[1]} for guess in guesses]}), 200
    except Exception as e:
        logging.error(f"Error fetching price guesses: {e}")
        return jsonify({'message': 'Failed to fetch price guesses.'}), 500

if __name__ == '__main__':
    PORT = 8000
    app.run(host='0.0.0.0', port=PORT, debug=True)
