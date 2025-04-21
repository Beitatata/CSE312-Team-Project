// maze.js
// Generates a perfect maze using the recursive backtracker algorithm

/**
 * generateMaze(rows, cols)
 * @param {number} rows  - number of rows in the grid
 * @param {number} cols  - number of columns in the grid
 * @returns {number[][]} - 2D array where 1 = wall, 0 = passage
 */
function generateMaze(rows, cols) {
  // Initialize all cells as walls
  const maze = Array.from({ length: rows }, () => Array(cols).fill(1));
  const stack = [];
  let r = 1, c = 1;

  // Start at (1,1)
  maze[r][c] = 0;
  stack.push([r, c]);

  while (stack.length) {
    const [row, col] = stack[stack.length - 1];
    const neighbors = [];

    // Check potential neighbors two steps away
    if (row > 1 && maze[row-2][col] === 1)       neighbors.push(['N', row-2, col]);
    if (row < rows-2 && maze[row+2][col] === 1)   neighbors.push(['S', row+2, col]);
    if (col > 1 && maze[row][col-2] === 1)       neighbors.push(['W', row, col-2]);
    if (col < cols-2 && maze[row][col+2] === 1)   neighbors.push(['E', row, col+2]);

    if (neighbors.length) {
      // Carve a random neighbor
      const [dir, nr, nc] = neighbors[Math.floor(Math.random() * neighbors.length)];
      if (dir === 'N') maze[row-1][col] = 0;
      if (dir === 'S') maze[row+1][col] = 0;
      if (dir === 'W') maze[row][col-1] = 0;
      if (dir === 'E') maze[row][col+1] = 0;
      maze[nr][nc] = 0;
      stack.push([nr, nc]);
    } else {
      // Backtrack
      stack.pop();
    }
  }

  return maze;
}

// Expose globally for game.js to consume
window.generateMaze = generateMaze;
