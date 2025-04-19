# MMO Game Project

A real-time multiplayer online game built with Flask/Python for the team project.

## Setup Instructions

### Prerequisites
- Docker and Docker Compose installed on your machine

### Running the Application
1. Clone the repository
   ```
   git clone <your-repo-url>
   cd <project-directory>
   ```

2. Start the application using Docker Compose
   ```
   docker compose up
   ```

3. Access the application in your browser
   ```
   http://localhost:8080
   ```

## Project Features

### Docker Compose
- Application runs on port 8080
- MongoDB database runs in a separate container

### Authentication
- User registration with salted and hashed passwords
- User login with secure session management
- HttpOnly cookies for authentication tokens
- Visual indicator for logged-in users

### Logging
- Server requests logged to a file outside the Docker container
- Logs include IP address, HTTP method, path, and timestamp

## Project Structure
```
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile            # Docker configuration for the app
├── app.py                # Main Flask application
├── requirements.txt      # Python dependencies
├── templates/            # HTML templates
│   ├── index.html        # Home page
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   └── game.html         # Game page (authenticated)
├── logs/                 # Server logs directory
└── README.md             # Project documentation
```

## Testing

Once the application is running:

1. Register a new account at http://localhost:8080/register
2. Login with your credentials at http://localhost:8080/login
3. After logging in, you'll see your username displayed on the home page
4. Click "Enter Game" to access the game page
5. You can move your character with the WASD keys
6. Check the logs directory for server request logs

## Security Features
- Passwords are salted and hashed using bcrypt
- Authentication tokens are stored as hashes in the database
- Cookies are set with HttpOnly flag