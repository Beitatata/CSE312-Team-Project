from flask import Flask, request, render_template, redirect, make_response, jsonify
from pymongo import MongoClient
import bcrypt
import secrets
import hashlib
import os
import logging
from datetime import datetime
from auth import extract_credentials, validate_password
import flask.cli
# ignore flask words
flask.cli.show_server_banner = lambda *args, **kwargs: None
# check it is in docker or not
in_docker = os.environ.get('IN_DOCKER') == '1'
if in_docker:
    logging.info("Flask app started, logging is working!")
else:
    logging.basicConfig(level=logging.ERROR)

    logging.getLogger('werkzeug').setLevel(logging.ERROR)

app = Flask(__name__, template_folder="public")
app.secret_key = os.environ.get("SECRET_KEY", "default-secret-key")

# Logging setup
logging.basicConfig(
    filename="/logs/access.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

# log
@app.before_request
def log_request():
    ip = request.remote_addr
    method = request.method
    path = request.path
    timestamp = datetime.utcnow().isoformat()
    logging.info(f"{timestamp} {ip} {method} {path}")


# MongoDB client
mongo_url = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
client = MongoClient(mongo_url)
db = client["myapp"]
users = db["users"]


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def get_authenticated_user():
    token = request.cookies.get("auth_token")
    if not token:
        return None
    token_hash = hash_token(token)
    return users.find_one({"token_hash": token_hash})


@app.route("/")
def index():
    user = get_authenticated_user()
    if user:
        return render_template("index.html", username=user["username"])
    return render_template("index.html", username=None)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username, password = extract_credentials(request)
    password2 = request.form.get("password2")

    if not username or not password or not password2:
        return jsonify({"error": "Missing fields"}), 400

    if password != password2:
        return jsonify({"error": "Passwords do not match"}), 400

    if not validate_password(password):
        return jsonify({"error": "Password does not meet security requirements"}), 400

    if users.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 409

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    users.insert_one({
        "username": username,
        "password": hashed_pw,
        "token_hash": None
    })

    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username, password = extract_credentials(request)

    user = users.find_one({"username": username})
    if not user:
        return jsonify({"error": "User not found"}), 400

    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Incorrect password"}), 400

    token = secrets.token_urlsafe(32)
    token_hash = hash_token(token)

    users.update_one({"username": username}, {"$set": {"token_hash": token_hash}})

    response = make_response(redirect("/"))
    response.set_cookie(
        "auth_token",
        token,
        httponly=True,
        max_age=60 * 60 * 24 * 7  # 7 days
    )
    return response


@app.route("/logout")
def logout():
    response = make_response(redirect("/"))
    response.set_cookie("auth_token", "", max_age=0)
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
