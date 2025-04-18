from flask import request
from flask_socketio import SocketIO, emit
from maze_layout import maze, start_position, goal_position
from app import app, hash_token, users, socketio




players = {}

def get_authenticated_user_from_request(req):
    print("🍪 all cookies from request:", req.cookies)
    token = req.cookies.get("auth_token")
    print("🍪 extracted auth_token =", token)
    if not token:
        return None
    token_hash = hash_token(token)
    user = users.find_one({"token_hash": token_hash})
    print("🧑 Matched user from DB:", user)
    return user


@socketio.on("connect")
def handle_connect():
    print("🔥 WebSocket connect triggered")  # ✅ 用于验证是否触发
    user = get_authenticated_user_from_request(request)
    print("🍪 all cookies from request:", request.cookies)  # ✅ 输出 cookie
    if not user:
        print("⛔ Rejected WebSocket connection: not authenticated.")
        return False

    username = user["username"]
    players[username] = {
        "row": start_position[0],
        "col": start_position[1]
    }
    print(f"✅ {username} connected via WebSocket.")
    print("📡 Broadcast on connect:", players)
    print(f"📊 Players after connect: {players}")

    # ✅ 广播所有玩家位置
    emit("all_positions", players, broadcast=True)
    print(f"📡 Broadcast players on connect: {players}")

@socketio.on("move")
def handle_move(data):
    user = get_authenticated_user_from_request(request)
    if not user:
        print("⛔ Move ignored: not authenticated.")
        return

    username = user["username"]
    if username not in players:
        print("⛔ Move ignored: unknown player.")
        return

    direction = data.get("direction")
    row, col = players[username]["row"], players[username]["col"]
    new_row, new_col = row, col

    if direction == "up":
        new_row = max(0, row - 1)
    elif direction == "down":
        new_row = min(len(maze) - 1, row + 1)
    elif direction == "left":
        new_col = max(0, col - 1)
    elif direction == "right":
        new_col = min(len(maze[0]) - 1, col + 1)

    if maze[new_row][new_col] == 1:
        print(f"🚧 Blocked by wall at ({new_row}, {new_col})")
        return

    players[username] = {"row": new_row, "col": new_col}
    emit("all_positions", players, broadcast=True)  # ✅ 广播给所有人
    print(f"📡 Broadcast all players: {players}")
    print(f"🟦 {username} moved to ({new_row}, {new_col})")

    if (new_row, new_col) == goal_position:
        print(f"🏁 {username} reached the goal!")
        emit("game_over", {"winner": username}, broadcast=True)

@socketio.on("disconnect")
def handle_disconnect():
    user = get_authenticated_user_from_request(request)
    if user:
        username = user["username"]
        players.pop(username, None)
        print(f"🔌 {username} disconnected.")


@socketio.on("request_players")
def handle_request_players():
    user = get_authenticated_user_from_request(request)
    if not user:
        return

    username = user["username"]
    print(f"📋 Player {username} requested player list")
    print(f"📊 Current players: {players}")

    # 确保请求的玩家在列表中
    if username not in players:
        players[username] = {
            "row": start_position[0],
            "col": start_position[1]
        }
        print(f"➕ Added missing player {username} to list")

    # 发送玩家列表
    emit("all_positions", players)