# CSE312-Team-Project
🕹 Multiplayer Maze Race – Project Summary
Overview:
Our game is a real-time multiplayer maze race where all players compete to reach the goal located at the bottom-right corner of a fixed-size maze. Each player starts at the top-left corner and can move in four directions (up, down, left, right) without passing through walls. The first player to reach the goal wins, and the game ends immediately upon a winner being determined.
🎮 Game Features
Fixed Maze Layout: The game map is a predefined 2D grid consisting of walls and open paths. The maze layout is identical for all players.
Simultaneous Multiplayer: All connected users participate in the same race in real time. Each player's position is updated and broadcast via WebSockets.
Movement Logic: Players can move one tile at a time using arrow keys or WASD, and movement is validated on the server to prevent wall collision.
Player Visibility: All players can see each other's positions and usernames in the maze.
Winner Announcement: Once a player reaches the goal tile, the server broadcasts a game-over event and identifies the winner.
🧰 Technical Implementation
Framework: Flask with Flask-SocketIO (Python)
Authentication: User registration/login system with hashed passwords and session-based authentication
WebSockets: Real-time updates for player movements using Socket.IO
Database: MongoDB container (for user accounts, stats, and optional achievements)
Dockerized: Runs via docker-compose on port 8080, with separate containers for app and DB
Logging: All HTTP requests, WebSocket events, login attempts, and errors are logged to a local file outside the container via a mounted volume
Deployment: Will be deployed on AWS with HTTPS and WSS enabled using Certbot and a custom domain
🏁 Win Condition
The game ends as soon as a player reaches the goal position in the maze. The winner is the first player to arrive, based on the server’s event order (i.e., the first move processed at the goal coordinates).
