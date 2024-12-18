from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import random
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from sql import get_connection
import logging
import base64
import threading
import time

load_dotenv()

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)

JWT_SECRET = os.getenv('JWT_SECRET', 'your_jwt_secret_key')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
JWT_EXP_DELTA_SECONDS = int(os.getenv('JWT_EXP_DELTA_SECONDS', 3600))

conn = get_connection()
cursor = conn.cursor()

current_car = None
current_round_start_time = None
lock = threading.Lock()

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

def select_new_car():
    global current_car, current_round_start_time
    while True:
        with lock:
            cursor.execute("""
                SELECT TOP 1 car_id, brand, model, kilometer, fuel_type, transmission, damage, year, price
                FROM cars
                WHERE car_id NOT IN (SELECT car_id FROM price_guesses)
                ORDER BY NEWID()
            """)
            new_car = cursor.fetchone()
            
            if new_car:
                car_id = new_car[0]
                brand = new_car[1]
                model = new_car[2]
                kilometer = new_car[3]
                fuel_type = new_car[4]
                transmission = new_car[5]
                damage = new_car[6]
                year = new_car[7]
                price = new_car[8]
                cursor.execute("""
                    SELECT image_data
                    FROM car_images
                    WHERE car_id = ?
                """, (car_id,))
                images = cursor.fetchall()
                image_urls = []
                for image in images:
                    image_data = image[0]
                    if image_data:
                        base64_image = base64.b64encode(image_data).decode('utf-8')
                        image_urls.append(f"data:image/jpeg;base64,{base64_image}")
                
                selected_images = random.choices(image_urls, k=min(10, len(image_urls)))
                
                current_car = {
                    'car_id': car_id,
                    'brand': brand,
                    'model': model,
                    'kilometer': kilometer,
                    'fuel_type': fuel_type,
                    'transmission': transmission,
                    'damage': damage,
                    'year': year,
                    'price': price,
                    'images': selected_images
                }
                
                current_round_start_time = datetime.now(timezone.utc)
                logging.info(f"New car selected: {brand} {model}, Price: {price}")
            else:
                current_car = None
                current_round_start_time = None
                logging.info("No new cars available.")
        
        time.sleep(15)  

@app.route('/get_new_car', methods=['GET'])
def get_new_car():
    if current_car and current_round_start_time:
        elapsed_time = (datetime.now(timezone.utc) - current_round_start_time).total_seconds()
        remaining_time = 15 - elapsed_time
        remaining_time = max(int(remaining_time), 0)

        return jsonify({**current_car, 'remaining_time': remaining_time}), 200
    else:
        return jsonify({'message': 'No active round or car selected.'}), 404

@app.route('/car_images/<int:car_id>', methods=['GET'])
def get_car_images(car_id):
    try:
        cursor.execute("""
            SELECT image_data
            FROM car_images
            WHERE car_id = ?
        """, (car_id,))
        images = cursor.fetchall()
        image_urls = []
        for image in images:
            image_data = image[0]
            if image_data:
                base64_image = base64.b64encode(image_data).decode('utf-8')
                image_urls.append(f"data:image/jpeg;base64,{base64_image}")
        if not image_urls:
            return jsonify({'message': 'No images found for this car.'}), 404
        return jsonify({'images': image_urls}), 200
    except Exception as e:
        logging.error(f"Error fetching car images: {e}")
        return jsonify({'message': 'Failed to fetch car images.'}), 500

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

@app.route('/categories', methods=['GET'])
def get_categories():
    try:
        cursor.execute("SELECT * FROM categories")
        categories = cursor.fetchall()
        return jsonify([{'category_id': category[0], 'category_name': category[1]} for category in categories]), 200
    except Exception as e:
        logging.error(f"Error fetching categories: {e}")
        return jsonify({'message': 'Failed to fetch categories.'}), 500

@app.route('/submit_guess', methods=['POST'])
@token_required
def submit_guess(current_user_id, current_username):
    data = request.get_json()
    car_id = data.get('car_id')
    guessed_price = data.get('guessed_price')

    if not car_id or not guessed_price:
        return jsonify({'message': 'Car ID and guessed price are required.'}), 400
    try:
        guessed_price = int(guessed_price)
        cursor.execute("""
            INSERT INTO price_guesses (car_id, user_id, guessed_price)
            VALUES (?, ?, ?)
        """, (car_id, current_user_id, guessed_price))
        cursor.connection.commit()

        return jsonify({'message': 'Price guess submitted successfully.'}), 200
    except ValueError:
        return jsonify({'message': 'Invalid guessed price format.'}), 400
    except Exception as e:
        logging.error(f"Error submitting guess: {e}")
        return jsonify({'message': 'Failed to submit guess.'}), 500

@app.route('/price_guesses/<int:car_id>', methods=['GET'])
def get_price_guesses(car_id):
    try:
        cursor.execute("""
            SELECT price FROM cars WHERE car_id = ?
        """, (car_id,))
        price_row = cursor.fetchone()
        if not price_row:
            return jsonify({'message': 'Car not found.'}), 404
        actual_price = price_row[0]
        cursor.execute("""
            SELECT u.username, pg.guessed_price
            FROM price_guesses pg
            INNER JOIN users u ON pg.user_id = u.user_id
            WHERE pg.car_id = ?
        """, (car_id,))
        guesses = cursor.fetchall()
        sorted_guesses = sorted(guesses, key=lambda x: abs(x[1] - actual_price))
        return jsonify({'car_id': car_id, 'guesses': [{'username': guess[0], 'guessed_price': guess[1]} for guess in sorted_guesses], 'actual_price': actual_price}), 200
    except Exception as e:
        logging.error(f"Error fetching price guesses: {e}")
        return jsonify({'message': 'Failed to fetch price guesses.'}), 500

if __name__ == '__main__':
    threading.Thread(target=select_new_car, daemon=True).start()
    
    PORT = 8000
    app.run(host='0.0.0.0', port=PORT, debug=True)
