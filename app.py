import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import json
from bson.objectid import ObjectId

# Initialize Flask app
app = Flask(__name__)
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
    headers = "; ".join(f"{k}: {v}" for k, v in request.headers.items ())
    cookies = "; ".join(f"{k}={v}" for k, v in request.cookies.items ())

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
        
    def is_authenticated():
        return True
        
    def is_active():
        return True
        
    def is_anonymous():
        return False
        
    def get_id(self):
        return self.id

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
            return redirect(url_for('game'))
        
        flash('Invalid username or password.')
    
    return render_template('login.html')

# Route for user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Route for the game (protected)
@app.route('/game')
@login_required
def game():
    return render_template('game.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)