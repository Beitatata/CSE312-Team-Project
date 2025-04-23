// Generates a perfect maze using the recursive backtracker algorithm with strict seed
function mulberry32(seed) {
  return function() {
    seed |= 0;
    seed = seed + 0x6D2B79F5 | 0;
    let t = Math.imul(seed ^ seed >>> 15, 1 | seed);
    t ^= t + Math.imul(t ^ t >>> 7, 61 | t);
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  }
}

/**
 * generateMaze(rows, cols, seed)
 * @param {number} rows
 * @param {number} cols
 * @param {number} seed - must be provided; if same, maze will be identical
 * @returns {number[][]}
 */
function generateMaze(rows, cols, seed) {
  const rand = mulberry32(seed); // 🚫 no fallback — seed MUST be provided

  const maze = Array.from({ length: rows }, () => Array(cols).fill(1));
  const stack = [];
  let r = 1, c = 1;

  maze[r][c] = 0;
  stack.push([r, c]);

  while (stack.length) {
    const [row, col] = stack[stack.length - 1];
    const neighbors = [];

    if (row > 1 && maze[row-2][col] === 1)       neighbors.push(['N', row-2, col]);
    if (row < rows-2 && maze[row+2][col] === 1)   neighbors.push(['S', row+2, col]);
    if (col > 1 && maze[row][col-2] === 1)       neighbors.push(['W', row, col-2]);
    if (col < cols-2 && maze[row][col+2] === 1)   neighbors.push(['E', row, col+2]);

    if (neighbors.length) {
      const [dir, nr, nc] = neighbors[Math.floor(rand() * neighbors.length)];
      if (dir === 'N') maze[row-1][col] = 0;
      if (dir === 'S') maze[row+1][col] = 0;
      if (dir === 'W') maze[row][col-1] = 0;
      if (dir === 'E') maze[row][col+1] = 0;
      maze[nr][nc] = 0;
      stack.push([nr, nc]);
    } else {
      stack.pop();
    }
  }

  return maze;
}

// Expose globally
window.generateMaze = generateMaze;
