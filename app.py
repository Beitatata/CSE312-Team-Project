import os
import random
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user,
    login_required, current_user
)
from flask_socketio import SocketIO, emit, join_room, leave_room
import uuid
import bcrypt
import json
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename

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



@app.route('/')
def index():
    return render_template('index.html')


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
        mongo.db.users.insert_one({
            'username': username,
            'password': password_hash,
            'created_at': datetime.now()
        })

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user_data = mongo.db.users.find_one({'username': username})
        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password']):
            user = User(user_data)
            login_user(user)

            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

        flash('Invalid username or password.')

    return render_template('login.html')

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

@app.route('/lobby')
@login_required
def lobby():
    return render_template('lobby.html', username=current_user.username)

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
def handle_disconnect():
    if current_user.is_authenticated:
        username = current_user.username
        online_users.discard(username)
        leave_room('lobby')
        emit('update_user_list', list(online_users), room='lobby')

    sid = request.sid

    for room, players in rooms.items():
        for username, player in list(players.items()):
            if player.get('sid') == sid:
                del rooms[room][username]
                emit('player_left', username, room=room)
                emit('update_players', list(rooms[room].keys()), room=room)
                break



# After receiving 'start_game' from frontend, broadcast from server\ n@socketio.on('start_game')
@socketio.on('start_game')
def handle_start_game(data):
    # 1) Generate a unique room name for this game
    seed = random.randint(0, 2**31-1)
    room = data.get('room') or str(uuid.uuid4())
    # 2) Notify all clients in the lobby: game started, go to /game?room=xxx
    emit('game_start', {'room': room, 'seed': seed}, room='lobby')

rooms = {}
@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    username = data['username']
    avatar_filename = current_user.avatar
    avatar_url = url_for('static', filename=f'uploads/{avatar_filename}') if avatar_filename else None
    sid = request.sid


    join_room(room)

    if room not in rooms:
        rooms[room] = {}

    rooms[room][username] = {
        'username': username,
        'avatarUrl': avatar_url,
        'row': 1,
        'col': 1,
        'sid': sid
    }

    # Acknowledge to the joining client: who is already in the room
    others = [v for k, v in rooms[room].items() if k != username]
    emit('join_game_ack', {'players': others})

    # Notify others: a new player has joined
    emit('player_joined', {
        'username': username,
        'avatarUrl': avatar_url,
        'row': 1,
        'col': 1
    }, room=room, include_self=False)

    # Sync player list for everyone
    emit('update_players', list(rooms[room].keys()), room=room)

@socketio.on('move')
def handle_move(data):
    room = data['room']
    username = data['username']
    row = data['row']
    col = data['col']

    # Update the server-side record of the player's position
    if room in rooms and username in rooms[room]:
        rooms[room][username]['row'] = row
        rooms[room][username]['col'] = col

    # Broadcast the move to other players (excluding the mover)
    emit('player_moved', {
        'username': username,
        'row': row,
        'col': col
    }, room=room, include_self=False)
    goal_row = 19
    goal_col = 19
    if row == goal_row and col == goal_col:
        print(f"[WIN] {username} has reached the goal!")
        emit('player_won', {'winner': username}, room=room)
# Routes

@app.route('/game')
@login_required
def game():
    room = request.args.get('room')
    return render_template('game.html', room=room, username=current_user.username)

# Configuration for file uploads
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

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

    socketio.run(app, host='0.0.0.0', port=8080, debug=False)
