// game.js — Multiplayer Maze Game (with debugging logs)
const socket = io();

const params = new URLSearchParams(window.location.search);
const ROOM = params.get('room');
const seed = parseInt(params.get('seed'), 10);
const numRows = 20, numCols = 20;
const goalR = numRows-1, goalC = numCols-1;

const maze = generateMaze(numRows, numCols, seed);

const USERNAME   = window.PLAYER_NAME || 'Guest';
const AVATAR_URL = window.PLAYER_IMG_URL || null;

socket.emit('join_room', { room: ROOM, username: USERNAME });

socket.on('update_players', players => {
  const ul = document.getElementById('player-names');
  ul.innerHTML = '';
  players.forEach(p => {
    const li = document.createElement('li');
    li.textContent = p;
    ul.appendChild(li);
  });
});

const canvas = document.getElementById('game-canvas');
const ctx    = canvas.getContext('2d');
const SIZE   = Math.min(canvas.clientWidth, canvas.clientHeight);
canvas.width  = SIZE;
canvas.height = SIZE;
const cell = SIZE / numRows;

const localPlayer = {
  username: USERNAME,
  avatarUrl: AVATAR_URL,
  row: 1,
  col: 1,
  x: cell + cell / 2,
  y: cell + cell / 2,
  img: (() => {
    if (AVATAR_URL) {
      const i = new Image();
      i.src = AVATAR_URL;
      return i;
    }
    return null;
  })()
};

const otherPlayers = {};

let moving = false;
let targetX = localPlayer.x, targetY = localPlayer.y;
const speed = 200;
const keys = {};
window.addEventListener('keydown', e => keys[e.key.toLowerCase()] = true);
window.addEventListener('keyup', e => keys[e.key.toLowerCase()] = false);

function tryStartMove(dr, dc) {
  if (moving) return;
  const nr = localPlayer.row + dr;
  const nc = localPlayer.col + dc;



  if (nr < 0 || nr >= numRows || nc < 0 || nc >= numCols || maze[nr][nc] === 1) {
    console.warn(`[MOVE] Blocked or invalid move to (${nr}, ${nc})`);
    return;
  }

  console.log(`[MOVE] Moving to (${nr}, ${nc})`);

  localPlayer.row = nr;
  localPlayer.col = nc;
  targetX = nc * cell + cell / 2;
  targetY = nr * cell + cell / 2;
  moving = true;

  socket.emit('move', { room: ROOM, username: USERNAME, row: nr, col: nc });
}

let lastTime = performance.now();
function loop(now) {


  const delta = (now - lastTime) / 1000;
  lastTime = now;

  if (moving) {
    const dx = targetX - localPlayer.x;
    const dy = targetY - localPlayer.y;
    const dist = Math.hypot(dx, dy);
    const step = speed * delta;
    if (step >= dist) {
      localPlayer.x = targetX;
      localPlayer.y = targetY;
      moving = false;
    } else {
      localPlayer.x += dx / dist * step;
      localPlayer.y += dy / dist * step;
    }
  } else {
    if (keys['w'] || keys['arrowup']) tryStartMove(-1, 0);
    else if (keys['s'] || keys['arrowdown']) tryStartMove(1, 0);
    else if (keys['a'] || keys['arrowleft']) tryStartMove(0, -1);
    else if (keys['d'] || keys['arrowright']) tryStartMove(0, 1);
  }

  drawMaze();
  Object.values(otherPlayers).forEach(p => {
      const dx = p.targetX - p.x;
      const dy = p.targetY - p.y;
      const dist = Math.hypot(dx, dy);
      const step = speed * delta;

      if (dist > 0.1) {
        p.x += dx / dist * Math.min(step, dist);
        p.y += dy / dist * Math.min(step, dist);
      }
      drawCircle(p.x, p.y, cell * 0.35, p.img, p.username);
  });
  drawCircle(localPlayer.x, localPlayer.y, cell * 0.35, localPlayer.img, localPlayer.username);


  requestAnimationFrame(loop);
}
requestAnimationFrame(loop);

function drawMaze() {
  ctx.clearRect(0, 0, SIZE, SIZE);
  ctx.fillStyle = '#222';
  for (let r = 0; r < numRows; r++)
    for (let c = 0; c < numCols; c++)
      if (maze[r][c]) ctx.fillRect(c * cell, r * cell, cell, cell);
  ctx.fillStyle = 'rgba(0,255,0,0.4)';
  ctx.fillRect(goalC * cell, goalR * cell, cell, cell);
}

function drawCircle(x, y, r, img, username) {
  if (img && img.complete && img.naturalWidth > 0) {
    ctx.save(); ctx.beginPath(); ctx.arc(x, y, r, 0, 2 * Math.PI); ctx.clip();
    ctx.drawImage(img, x - r, y - r, 2 * r, 2 * r); ctx.restore();
  } else {
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--primary-color').trim();
    ctx.beginPath(); ctx.arc(x, y, r, 0, 2 * Math.PI); ctx.fill();
    ctx.fillStyle = '#fff'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.font = '8px Orbitron'; ctx.fillText(username, x, y);
  }
}

// Socket handlers for players
socket.on('join_game_ack', data => {

  data.players.forEach(p => {
    if (p.username !== USERNAME) {
      otherPlayers[p.username] = {
        username: p.username,
        avatarUrl: p.avatarUrl,
        row: p.row, col: p.col,
        x: p.col * cell + cell / 2,
        y: p.row * cell + cell / 2,
        targetX: p.col * cell + cell / 2,
        targetY: p.row * cell + cell / 2,
        img: (() => {
          if (!p.avatarUrl || p.avatarUrl === 'null') return null;  // Do not load invalid avatars
          const i = new Image();
          i.src = p.avatarUrl;
          return i;
        })()
      };
    }
  });
});

socket.on('player_joined', p => {
  console.log('[player_joined]', p.username, 'avatarUrl:', p.avatarUrl);
  if (p.username !== USERNAME) {
    otherPlayers[p.username] = {
      ...p,
      x: p.col * cell + cell / 2,
      y: p.row * cell + cell / 2,
      targetX: p.col * cell + cell/2,
      targetY: p.row * cell + cell/2,
      img: (() => {
          if (!p.avatarUrl || p.avatarUrl === 'null') return null;  // Do not load invalid avatars
          const i = new Image();
          i.src = p.avatarUrl;
          return i;
        })()
    };
  }
});


socket.on('player_moved', p => {
  if (p.username !== USERNAME && otherPlayers[p.username]) {
    otherPlayers[p.username].row = p.row;
    otherPlayers[p.username].col = p.col;
    otherPlayers[p.username].targetX = p.col * cell + cell / 2;
    otherPlayers[p.username].targetY = p.row * cell + cell / 2;
  }
});
socket.on('player_left', username => {
  console.log('[SOCKET] player_left:', username);
  delete otherPlayers[username];
});

let gameOver = false;

socket.on('player_won', data => {
  if (gameOver) return;
  gameOver = true;

  if (data.winner === USERNAME) {
    setTimeout(() => {
      alert('🎉 You Win!');
      window.location.href = '/';
    }, 200);  // Delay prompt again by 200ms
  } else {
    setTimeout(() => {
        alert('💥 ' + data.winner + ' Wins! You Lose!');
        window.location.href = '/';
     },200);
  }
});
