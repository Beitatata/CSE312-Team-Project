// static/game.js
console.log("🧪 Document.cookie =", document.cookie);

const socket = io({
  transports: ["websocket"],
  upgrade: false,
  withCredentials: true
}); // 连接 WebSocket（后面服务器端会配置 Flask-SocketIO）

socket.on("connect", () => {
  console.log("✅ Connected to server via WebSocket!");
  socket.emit("request_players");
});

socket.on("connect_error", (err) => {
  console.error("❌ Connection failed:", err.message);
});

const canvas = document.getElementById("gameCanvas");
const ctx = canvas.getContext("2d");

const rows = 8, cols = 8;
const cellSize = canvas.width / cols;

// 示例迷宫地图（后面可以从后端获取）
let maze = [
  [0, 1, 0, 0, 0, 0, 0, 0],
  [0, 1, 0, 1, 1, 1, 0, 1],
  [0, 0, 0, 1, 0, 0, 0, 1],
  [0, 1, 1, 1, 0, 1, 0, 0],
  [0, 0, 0, 0, 0, 1, 1, 0],
  [1, 1, 1, 1, 0, 0, 0, 0],
  [0, 0, 0, 1, 1, 1, 1, 0],
  [0, 1, 0, 0, 0, 0, 0, 0]
];

let myPosition = { row: 0, col: 0 };

// 键盘控制
document.addEventListener("keydown", (event) => {
  const key = event.key.toLowerCase();
  let dir = null;
  if (["arrowup", "w"].includes(key)) dir = "up";
  else if (["arrowdown", "s"].includes(key)) dir = "down";
  else if (["arrowleft", "a"].includes(key)) dir = "left";
  else if (["arrowright", "d"].includes(key)) dir = "right";
  if (dir) {
    socket.emit("move", { direction: dir });
  }
});

// 监听后端传来的位置更新
let allPlayers = {};
let myUsername = window.myUsername || null;

socket.on("all_positions", (data) => {
  console.log("📦 all_positions received:", data);
  console.log("📊 Players count:", Object.keys(data).length);
  allPlayers = data;
  drawMaze();
});


// 游戏结束
socket.on("game_over", (data) => {
  document.getElementById("status").textContent = `🏁 ${data.winner} won the race!`;
});

// 画地图和自己
function drawMaze() {
  console.log("🎯 drawing with myUsername =", myUsername);
  console.log("🧍 allPlayers =", JSON.stringify(allPlayers));  // 更详细的日志

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  // 绘制迷宫
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      ctx.fillStyle = maze[r][c] === 1 ? "black" : "white";
      ctx.fillRect(c * cellSize, r * cellSize, cellSize, cellSize);
      ctx.strokeRect(c * cellSize, r * cellSize, cellSize, cellSize);
    }
  }

  // 绘制玩家
  for (const [username, pos] of Object.entries(allPlayers)) {
    console.log(`🎮 Drawing player ${username} at (${pos.row}, ${pos.col})`);  // 新增：记录每个玩家的绘制
    ctx.fillStyle = (username === myUsername) ? "blue" : "red";
    ctx.beginPath();
    ctx.arc(
      pos.col * cellSize + cellSize / 2,
      pos.row * cellSize + cellSize / 2,
      cellSize / 3,
      0,
      2 * Math.PI
    );
    ctx.fill();
  }
}
// 初始渲染
drawMaze();
