import os
import logging

from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)
import bcrypt
import json
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room

# Initialize Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "default_secret_key")
app.config["MONGO_URI"] = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/mmo_game")

# Configure logging directory and logger
logs_dir = 'logs'
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

logging.basicConfig(
    filename=os.path.join(logs_dir, 'server.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Middleware to log each request's details
@app.before_request
def log_request_info():
    headers = "; ".join(f"{k}: {v}" for k, v in request.headers.items())
    cookies = "; ".join(f"{k}={v}" for k, v in request.cookies.items())

    log_data = {
        'ip': request.remote_addr,
        'method': request.method,
        'path': request.path,
        'timestamp': datetime.now().isoformat(),
        'headers': headers,
        'cookies': cookies
    }
    logging.info(json.dumps(log_data))

# Initialize MongoDB client
mongo = PyMongo(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model for authentication
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.password_hash = user_data['password']
        self.avatar = user_data.get('avatar')

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

# Home page route
@app.route('/')
def index():
    return render_template('index.html')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username is already taken
        if mongo.db.users.find_one({'username': username}):
            flash('Username already exists.')
            return redirect(url_for('register'))

        # Hash the password with bcrypt
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Insert new user into the database
        user_id = mongo.db.users.insert_one({
            'username': username,
            'password': password_hash,
            'created_at': datetime.now()
        }).inserted_id

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Retrieve user from database
        user_data = mongo.db.users.find_one({'username': username})

        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password']):
            user = User(user_data)
            login_user(user)

            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

        flash('Invalid username or password.')

    return render_template('login.html')

# User logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
# Initialize SocketIO and track online users

socketio = SocketIO(app,
                   cors_allowed_origins="*",
                   ssl_context=None)
online_users = set()

@socketio.on('join_lobby')
def handle_join_lobby():
    if current_user.is_authenticated:
        username = current_user.username
        online_users.add(username)
        join_room('lobby')
        emit('update_user_list', list(online_users), room='lobby')

@socketio.on('leave_lobby')
def handle_leave_lobby():
    if current_user.is_authenticated:
        username = current_user.username
        online_users.discard(username)
        leave_room('lobby')
        emit('update_user_list', list(online_users), room='lobby')

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        username = current_user.username
        online_users.discard(username)
        leave_room('lobby')
        emit('update_user_list', list(online_users), room='lobby')

# Protected game route
@app.route('/lobby')
@login_required
def lobby():
    return render_template('lobby.html', username=current_user.username)

@app.route('/game')
@login_required
def game():
    return render_template('game.html')

# Configuration for file uploads
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Flask requires a secret key for flash messages
app.secret_key = os.environ.get("SECRET_KEY", "default_secret_key")

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

# This is the upload_picture route you need
@app.route('/upload', methods=['POST'])
@login_required
def upload_picture():
    if 'picture' not in request.files:
        flash('No file part')
        return redirect(request.referrer or '/')

    file = request.files['picture']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.referrer or '/')

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Save the avatar filename to the current user's document
        mongo.db.users.update_one(
            {'_id': ObjectId(current_user.get_id())},
            {'$set': {'avatar': filename}}
        )

        flash('Upload successful!')
        return redirect(request.referrer or '/')

    flash('Invalid file type')
    return redirect(request.referrer or '/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
