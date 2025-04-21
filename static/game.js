// game.js top: global declarations
let playerImg = null;

// then immediately assign it
playerImg = new Image();
playerImg.src = window.PLAYER_IMG_URL;
// -- Global state --
const canvas = document.getElementById('game-canvas');
const ctx    = canvas.getContext('2d');
const SIZE   = Math.min(canvas.clientWidth, canvas.clientHeight);
canvas.width  = SIZE;
canvas.height = SIZE;
const player = {
  row:       1,
  col:       1,
  username:  window.PLAYER_NAME || 'Guest',
  avatarUrl: window.PLAYER_IMG_URL || null,
  avatarImg: null
};
if (player.avatarUrl) {
  player.avatarImg = new Image();
  player.avatarImg.src = player.avatarUrl;
}
const numRows = 20, numCols = 20;
const maze    = generateMaze(numRows, numCols);
const goalR   = numRows - 2, goalC = numCols - 2;
maze[goalR][goalC] = 0;

const cell = SIZE / numRows;

// Player uses pixel coordinates to render
let playerPx = cell + cell/2;  // initial x = col 1
let playerPy = cell + cell/2;  // initial y = row 1
let playerRow = 1, playerCol = 1;

// movement state
let moving    = false;
let targetX   = playerPx;
let targetY   = playerPy;
const speed   = 200; // pixels/second

// keyboard input
const keys = {};
window.addEventListener('keydown',  e => keys[e.key.toLowerCase()] = true);
window.addEventListener('keyup',    e => keys[e.key.toLowerCase()] = false);

// Attempt to start a smooth move
function tryStartMove(dr, dc) {
  if (moving) return;
  const nr = playerRow + dr, nc = playerCol + dc;
  if (nr<0||nr>=numRows||nc<0||nc>=numCols||maze[nr][nc]===1) return;
  // set target row/col
  playerRow = nr;
  playerCol = nc;
  targetX   = nc*cell + cell/2;
  targetY   = nr*cell + cell/2;
  moving    = true;
}

// Update each frame, delta is in milliseconds
let lastTime = performance.now();
function loop(now) {
  const delta = (now - lastTime) / 1000; // convert to seconds
  lastTime    = now;

  if (moving) {
    // Calculate the distance to move
    const dx = targetX - playerPx;
    const dy = targetY - playerPy;
    const dist = Math.hypot(dx, dy);
    const step = speed * delta;

    if (step >= dist) {
      // If reached or passed the target, snap to it
      playerPx = targetX;
      playerPy = targetY;
      moving   = false;
    } else {
      // Move proportionally
      playerPx += dx / dist * step;
      playerPy += dy / dist * step;
    }
  } else {
    // If not moving, listen for new keys to start moving
    if (keys['w'] || keys['arrowup'])    tryStartMove(-1, 0);
    else if (keys['s'] || keys['arrowdown']) tryStartMove( 1, 0);
    else if (keys['a'] || keys['arrowleft']) tryStartMove( 0,-1);
    else if (keys['d'] || keys['arrowright'])tryStartMove( 0, 1);
  }

  // Draw
  drawMaze();
  // Draw player: use playerPx/playerPy
  drawPlayer();

  // Check win condition
  if (!moving && playerRow===goalR && playerCol===goalC) {
    setTimeout(() => {
      alert('🎉 You Win!');
      // After pressing OK, return to homepage
      window.location.href = '/';
    }, 50);
    return; // Stop the loop
  }

  requestAnimationFrame(loop);
}

// Start the loop
requestAnimationFrame(loop);

// Maze drawing remains unchanged
function drawMaze() {
  ctx.clearRect(0,0,SIZE,SIZE);
  ctx.fillStyle = '#222';
  for (let r=0; r<numRows; r++) {
    for (let c=0; c<numCols; c++) {
      if (maze[r][c]) ctx.fillRect(c*cell, r*cell, cell, cell);
    }
  }
  // Draw the exit
  ctx.fillStyle = 'rgba(0,255,0,0.4)';
  ctx.fillRect(goalC*cell, goalR*cell, cell, cell);
}

function drawPlayer() {
  const x = playerPx, y = playerPy, r = cell * 0.35;

  // Only draw avatar when playerImg is non-null, loaded, and has valid dimensions
  if (playerImg && playerImg.complete && playerImg.naturalWidth > 0) {
    ctx.save();
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.clip();
    ctx.drawImage(playerImg, x - r, y - r, r * 2, r * 2);
    ctx.restore();
  } else {
    // Fallback: draw a default solid circle
    ctx.fillStyle = getComputedStyle(document.documentElement)
                     .getPropertyValue('--primary-color').trim();
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle    = '#fff';
    ctx.textAlign    = 'center';
    ctx.textBaseline = 'middle';
    ctx.font         = '8px Orbitron';
    ctx.fillText(player.username, x, y);
  }
}
