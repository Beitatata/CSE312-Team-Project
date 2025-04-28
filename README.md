
# MMO Maze Game

A multiplayer online maze game built with Flask and Socket.IO.

## Deployment Link

The game is deployed and can be accessed at:
https://cse312tictactoe.cse312.dev

## Project Overview

This is a multiplayer online maze game where players can move through a maze using WASD keys and interact with other players in real-time. The first player to reach the bottom-right corner of the maze wins.

## Features

- User registration and login system
- User avatar upload functionality
- Real-time multiplayer game lobby
- Randomly generated mazes based on seed values
- Real-time player position synchronization
- Win conditions and game completion notifications

## Technology Stack

- **Backend**: Flask, Flask-SocketIO, Flask-Login
- **Database**: MongoDB
- **Frontend**: JavaScript, HTML5 Canvas
- **Real-time Communication**: Socket.IO
- **Containerization**: Docker & Docker Compose
- **Security**: HTTPS, WSS, bcrypt password encryption

## Local Setup

To run this application locally:

1. Clone the repository
   ```
   git clone <your-repo-url>
   cd <project-directory>
   ```
2. Create a .env file in the project root directory, referring to the .env.example file format

3. Start the application using Docker Compose
   ```
   docker compose up
   ```

4. Access in your browser
   ```
   http://localhost:8080
   ```

## Security Measures

This project implements several security measures:
- Passwords are salted and hashed using bcrypt
- Persistent sessions with HttpOnly cookies
- Secure file upload handling
- HTTPS and WSS in production environment
- MongoDB limited to internal container access only
