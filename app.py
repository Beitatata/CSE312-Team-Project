import os
import random
import logging
import traceback
import json
import pytz
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, Response, g
from flask_pymongo import PyMongo
from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user,
    login_required, current_user
)
from flask_socketio import SocketIO, emit, join_room, leave_room
import uuid
import bcrypt
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import io

load_dotenv()

app_timezone = pytz.timezone('America/New_York')


def get_current_time():
    return datetime.now(app_timezone)


def format_timestamp(dt=None):
    if dt is None:
        dt = get_current_time()
    return dt.isoformat()


# Initialize Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["MONGO_URI"] = os.environ.get("MONGODB_URI", "mongodb://mongo:27017/mmo_game")
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB

# Configure logging directories
logs_dir = 'logs'
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

# Setup main application logger
logging.basicConfig(
    filename=os.path.join(logs_dir, 'server.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('mmo_game')

# Setup separate logger for raw HTTP requests/responses
http_logger = logging.getLogger('http_raw')
http_logger.setLevel(logging.INFO)
http_handler = logging.FileHandler(os.path.join(logs_dir, 'http_raw.log'))
http_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
http_logger.addHandler(http_handler)

# Maximum size for logging raw HTTP content (2048 bytes)
MAX_HTTP_LOG_SIZE = 2048


# Class to capture and log response data
class LoggingMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Create a response wrapper to capture status code
        response_captured = {}

        def _start_response(status, headers, exc_info=None):
            response_captured['status'] = status
            response_captured['headers'] = headers
            return start_response(status, headers, exc_info)

        # Process request as normal
        output = self.app(environ, _start_response)

        # Capture the response body, if needed
        response_body = b''
        for chunk in output:
            response_body += chunk
            yield chunk

        # Log raw HTTP response (headers only for non-text or if over size limit)
        try:
            is_text = False
            content_type = None
            for name, value in response_captured['headers']:
                if name.lower() == 'content-type' and ('text/' in value.lower() or 'application/json' in value.lower()):
                    is_text = True
                    content_type = value

            # Remove auth tokens from headers
            filtered_headers = []
            for name, value in response_captured['headers']:
                if name.lower() == 'set-cookie':
                    parts = value.split(';')
                    if any(part.strip().startswith('session=') for part in parts) or any(
                            part.strip().startswith('auth_token=') for part in parts):
                        cookie_parts = [part for part in parts if not (
                                part.strip().startswith('session=') or
                                part.strip().startswith('auth_token=')
                        )]
                        if cookie_parts:
                            filtered_headers.append((name, '; '.join(cookie_parts)))
                    else:
                        filtered_headers.append((name, value))
                else:
                    filtered_headers.append((name, value))

            response_log = {
                'status': response_captured['status'],
                'headers': dict(filtered_headers)
            }

            # Log body for text responses if under size limit
            if is_text and len(response_body) <= MAX_HTTP_LOG_SIZE:
                try:
                    response_log['body'] = response_body.decode('utf-8')
                except UnicodeDecodeError:
                    response_log['body'] = '[Unable to decode response body]'
            elif is_text:
                response_log['body'] = f'[Text content truncated to {MAX_HTTP_LOG_SIZE} bytes]'
                response_log['body_sample'] = response_body[:MAX_HTTP_LOG_SIZE].decode('utf-8', errors='ignore')
            else:
                response_log['body'] = '[Binary content, headers only]'

            http_logger.info(f"RESPONSE: {json.dumps(response_log)}")
        except Exception as e:
            logger.error(f"Error logging response: {str(e)}")
            logger.error(traceback.format_exc())


# Register middleware
app.wsgi_app = LoggingMiddleware(app.wsgi_app)


# Middleware to log each request's details
@app.before_request
def log_request_info():
    try:
        # Extract headers and cookies
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() != 'authorization' and k.lower() != 'cookie'}

        # Filter out sensitive cookies (like session tokens)
        cookies = {}
        for k, v in request.cookies.items():
            if k != 'session' and k != 'auth_token':  # Skip token
                cookies[k] = v

        # Base log data
        log_data = {
            'ip': request.remote_addr,
            'method': request.method,
            'path': request.path,
            'timestamp': format_timestamp(),
            'headers': headers,
            'cookies': cookies
        }

        # Add username to log if user is authenticated
        if current_user.is_authenticated:
            log_data['username'] = current_user.username

        # Log to main application log
        logger.info(json.dumps(log_data))

        # Log raw HTTP request (headers only for sensitive routes or non-text content)
        is_sensitive = request.path in ['/login', '/register']

        # Filter request headers (remove auth tokens)
        filtered_headers = {}
        for k, v in request.headers.items():
            if k.lower() == 'cookie':
                # Parse cookies and remove session
                cookie_parts = v.split(';')
                filtered_cookies = [c for c in cookie_parts if not (
                        c.strip().startswith('session=') or
                        c.strip().startswith('auth_token=')
                )]
                if filtered_cookies:
                    filtered_headers[k] = '; '.join(filtered_cookies)
            elif k.lower() != 'authorization':
                filtered_headers[k] = v

        request_log = {
            'method': request.method,
            'path': request.path,
            'headers': filtered_headers
        }

        # For non-sensitive routes with text content, include body if under size limit
        if not is_sensitive and request.content_length and request.content_length <= MAX_HTTP_LOG_SIZE:
            content_type = request.headers.get('Content-Type', '')
            if 'text/' in content_type.lower() or 'application/json' in content_type.lower():
                # Keep original position in the stream
                position = request.stream.tell()
                # Read content
                content = request.stream.read(MAX_HTTP_LOG_SIZE)
                # Reset position
                request.stream.seek(position)

                try:
                    request_log['body'] = content.decode('utf-8')
                except UnicodeDecodeError:
                    request_log['body'] = '[Unable to decode request body]'
            else:
                request_log['body'] = '[Binary content, headers only]'
        elif is_sensitive:
            request_log['body'] = '[Sensitive content, headers only]'
        elif request.content_length and request.content_length > MAX_HTTP_LOG_SIZE:
            request_log['body'] = f'[Content truncated, over {MAX_HTTP_LOG_SIZE} bytes]'

        http_logger.info(f"REQUEST: {json.dumps(request_log)}")

    except Exception as e:
        logger.error(f"Error logging request: {str(e)}")
        logger.error(traceback.format_exc())


# Log response status code after each request
@app.after_request
def log_response_info(response):
    try:
        log_data = {
            'method': request.method,
            'path': request.path,
            'status_code': response.status_code,
            'timestamp': format_timestamp()
        }

        # Add username to log if user is authenticated
        if current_user.is_authenticated:
            log_data['username'] = current_user.username

        logger.info(f"Response: {json.dumps(log_data)}")
    except Exception as e:
        logger.error(f"Error logging response: {str(e)}")
        logger.error(traceback.format_exc())

    return response


# Error handling with logging
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the stack trace
    logger.error(f"Unhandled exception: {str(e)}")
    logger.error(traceback.format_exc())

    # Return an error response
    return render_template('error.html', error=str(e)), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template('error.html', error="Uploaded file is too large (maximum 2MB allowed)."), 413


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
        self.won = 0
        self.lose = 0
        self.played = 0
        self.exp = 0
        self.level = 1

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
        existing_user = mongo.db.users.find_one({'username': username})

        if existing_user:
            # Log failed registration attempt
            logger.warning(f"Registration failed: Username '{username}' already exists.")
            flash('Username already exists.')
            return redirect(url_for('register'))

        # Hash the password with bcrypt
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Insert new user into the database
        mongo.db.users.insert_one({
            'username': username,
            'password': password_hash,
            "won": 0,
            "lose": 0,
            "played": 0,
            "exp": 0,
            "level": 1,
            'created_at': format_timestamp()
        })

        # Log successful registration
        logger.info(f"Registration successful: User '{username}' created.")

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user_data = mongo.db.users.find_one({'username': username})

        if not user_data:
            # Log failed login attempt - user doesn't exist
            logger.warning(f"Login failed: Username '{username}' does not exist.")
            flash('Invalid username or password.')
            return render_template('login.html'), 400

        if bcrypt.checkpw(password.encode('utf-8'), user_data['password']):
            user = User(user_data)
            login_user(user)

            # Log successful login
            logger.info(f"Login successful: User '{username}' logged in.")

            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            # Log failed login attempt - wrong password
            logger.warning(f"Login failed: User '{username}' tried to log in with the wrong password.")
            flash('Invalid username or password.')
            return render_template('login.html'), 400

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()

    # Log logout
    logger.info(f"Logout: User '{username}' logged out.")

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

        # Log user joined lobby
        logger.info(f"Socket: User '{username}' joined lobby.")


@socketio.on('leave_lobby')
def handle_leave_lobby():
    if current_user.is_authenticated:
        username = current_user.username
        online_users.discard(username)
        leave_room('lobby')
        emit('update_user_list', list(online_users), room='lobby')

        # Log user left lobby
        logger.info(f"Socket: User '{username}' left lobby.")


@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        username = current_user.username
        online_users.discard(username)
        leave_room('lobby')
        emit('update_user_list', list(online_users), room='lobby')
        mongo.db.ingame.update_one({"players": username}, {"$pull": {"players": username}})

        # Log user disconnected
        logger.info(f"Socket: User '{username}' disconnected.")

    sid = request.sid

    for room, players in rooms.items():
        for username, player in list(players.items()):
            if player.get('sid') == sid:
                del rooms[room][username]
                emit('player_left', username, room=room)
                emit('update_players', list(rooms[room].keys()), room=room)

                # Log player left game
                logger.info(f"Game: Player '{username}' left game room '{room}'.")
                break


@socketio.on('start_game')
def handle_start_game(data):
    # 1) Generate a unique room name for this game
    seed = random.randint(0, 2 ** 31 - 1)
    room = data.get('room') or str(uuid.uuid4())
    mongo.db.ingame.delete_many({"players": []})
    mongo.db.ingame.insert_one({"room": room, "players": []})

    # Log game starting
    if current_user.is_authenticated:
        logger.info(f"Game: User '{current_user.username}' started a new game with room '{room}' and seed {seed}.")

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

    # Log player joined game room
    logger.info(f"Game: Player '{username}' joined game room '{room}'.")

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

    mongo.db.ingame.update_one({"room": room}, {"$push": {"players": username}})
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

    goal_row = 1
    goal_col = 2
    goal_row2 = 2
    goal_col2 = 1
    if (row == goal_row and col == goal_col) or (row == goal_row2 and col == goal_col2):
        logger.info(f"Game: Player '{username}' has won the game in room '{room}'!")
        players = mongo.db.ingame.find_one({"room": room})
        players = players["players"]
        for player in players:
            if player == username:
                mongo.db.users.update_one({"username": username}, {"$inc": {"won": 1}})
                mongo.db.users.update_one({"username": username}, {"$inc": {"exp": 10}})
                temp = mongo.db.users.find_one({"username": player})
                if temp:
                    if temp.get("exp", 0) >= 100:
                        new_level = temp.get("level", 1) + 1
                        new_exp = temp["exp"] - 100
                        mongo.db.users.update_one(
                            {"username": player},
                            {"$set": {"level": new_level, "exp": new_exp}}
                        )
            else:
                mongo.db.users.update_one({"username": player}, {"$inc": {"lose": 1}})
                mongo.db.users.update_one({"username": player}, {"$inc": {"exp": 2}})
                temp = mongo.db.users.find_one({"username": player})
                if temp:
                    if temp.get("exp", 0) >= 100:
                        new_level = temp.get("level", 1) + 1
                        new_exp = temp["exp"] - 100
                        mongo.db.users.update_one(
                            {"username": player},
                            {"$set": {"level": new_level, "exp": new_exp}}
                        )
            mongo.db.users.update_one({"username": player}, {"$inc": {"played": 1}})
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
        logger.warning(
            f"Upload failed: User '{current_user.username}' attempted to upload but no file part was included.")
        flash('No file part')
        return redirect(request.referrer or '/')

    file = request.files['picture']
    if file.filename == '':
        logger.warning(f"Upload failed: User '{current_user.username}' attempted to upload but no file was selected.")
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

        logger.info(f"Upload successful: User '{current_user.username}' uploaded avatar '{filename}'.")
        flash('Upload successful!')
        return redirect(request.referrer or '/')

    logger.warning(f"Upload failed: User '{current_user.username}' attempted to upload an invalid file type.")
    flash('Invalid file type')
    return redirect(request.referrer or '/')

@app.route('/records')
@login_required
def record():
    username = current_user.username
    user = mongo.db.users.find_one({'username': username}, {'won': 1, 'lose': 1, 'played': 1, '_id': 0})
    if not user:
        return "user not found", 404
    return render_template('record.html', stats=user)

@app.route('/leaderboard')
def leaderboard():
    top_players = mongo.db.users.find(
        {},
        {'username': 1, 'won': 1, '_id': 0}
    ).sort('won', -1).limit(10)

    players = list(top_players)
    return render_template('leaderboard.html', players=players)



# Error template route - for error handling testing
@app.route('/trigger-error')
def trigger_error():
    # Deliberately cause an error to test error logging
    raise Exception("This is a deliberate error to test error logging")


# Wrap the application in a try/except to catch all unhandled errors
try:
    if __name__ == '__main__':
        socketio.run(app, host='0.0.0.0', port=8080, debug=False)
except Exception as e:
    # Log any unhandled errors that might occur during startup
    logger.critical(f"Critical error on application startup: {str(e)}")
    logger.critical(traceback.format_exc())
    raise  # Re-raise the exception after logging