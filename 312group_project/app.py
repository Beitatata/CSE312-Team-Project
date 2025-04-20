import os
import logging
import uuid
from datetime import datetime
from pickle import FALSE

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import json
from bson.objectid import ObjectId
from pymongo import MongoClient


# Initialize Flask app
app = Flask(__name__)
socketio = SocketIO(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "default_secret_key")
app.config["MONGO_URI"] = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/mmo_game")

# Configure logging
logs_dir = 'logs'
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

logging.basicConfig(
    filename=os.path.join(logs_dir, 'server.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# Configure request logger
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


# Initialize MongoDB
mongo = PyMongo(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User model
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.password_hash = user_data['password']

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

client = MongoClient("mongodb://localhost:27017/")
db = client["mmo_game"]
rooms_collection = db["rooms"]



# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None


# Route for the home page
@app.route('/')
def index():
    return render_template('index.html')


# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if username already exists
        if mongo.db.users.find_one({'username': username}):
            flash('Username already exists.')
            return redirect(url_for('register'))

        # Generate salt and hash the password
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Create user in database
        user_id = mongo.db.users.insert_one({
            'username': username,
            'password': password_hash,
            'created_at': datetime.now()
        }).inserted_id

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Find user in database
        user_data = mongo.db.users.find_one({'username': username})

        if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password']):
            user = User(user_data)

            login_result = login_user(user)
            # print(f"Login result: {login_result}") 

            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('lobby'))

        flash('Invalid username or password.')

    return render_template('login.html')


# Route for user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/game/<game_id>',methods=["GET","POST"], strict_slashes=False)
@login_required
def gamePage(game_id):
    return render_template('game.html',game_id=game_id)


# Route for the game (protected)
# @app.route('/api/game/', methods=["GET", "POST"], strict_slashes=False)
# @login_required
# def game():
#     return render_template('game.html')


@app.route('/lobby')
@login_required
def lobby():
    return render_template('lobby.html')


@app.route('/api/game-rooms', methods=['GET', 'POST'])
def create_room():
    if request.method == 'POST':
        try:
            # 从请求中获取 JSON 数据
            data = request.get_json()
            print(data)

            # 检查是否提供了房间名称
            if not data or 'name' not in data:
                return jsonify({"error": "Room name is required"}), 400

            # 生成唯一的房间 ID
            call_id = str(uuid.uuid4())

            # 将房间数据插入到 MongoDB 的 `room` 集合中
            mongo.db.room.insert_one({
                "id": call_id,
                "name": data["name"],
                "owner": data["username"],
                "created_at": datetime.now().isoformat()
            })

            # 返回创建成功的响应
            return jsonify({"id": call_id}), 201  # 状态码 201 表示已成功创建
        except Exception as e:
            # 处理异常并返回错误信息
            return jsonify({"error": "Bad Request", "message": str(e)}), 400

@app.route("/get_rooms", methods=["GET"])
def get_rooms():
    """从 MongoDB 获取所有房间数据"""
    rooms = list(rooms_collection.find({}, {"_id": 0}))  # 返回所有房间信息，不包含 `_id`
    return jsonify(rooms)


@app.route("/join_room", methods=["POST"])
def join_room():
    """处理玩家加入房间请求"""
    room_id = request.json.get("room_id")
    player_name = request.json.get("player_name")

    if not room_id or not player_name:
        return jsonify({"error": "房间ID或玩家名称缺失"}), 400

    # 检查房间是否存在
    room = rooms_collection.find_one({"id": room_id})
    if not room:
        return jsonify({"error": "房间不存在"}), 404

    # 添加玩家到房间（假设有一个 players 列表存储玩家名称）
    rooms_collection.update_one(
        {"id": room_id},
        {"$push": {"players": player_name}}
    )

    return jsonify({"message": f"{player_name} 已加入房间 {room_id}"}), 200



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
