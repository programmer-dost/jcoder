# jcoder - JWT Authentication API

A complete JWT-based authentication system built with TypeScript, Express.js, and SQLite.

## Features

### Authentication
- User signup and login with JWT tokens
- Multiple JWT algorithms support (HMAC: HS256/384/512, RSA: RS256/384/512)
- Customizable token expiration duration
- Optional refresh token functionality
- Secure password hashing with scrypt
- Protected routes with JWT middleware

### JWT Library
- Custom JWT implementation from scratch
- Support for both HMAC and RSA algorithms
- Base64URL encoding/decoding utilities
- Comprehensive token validation

### Database
- SQLite database with users and refresh_tokens tables
- Automatic database initialization
- Proper indexing and foreign key constraints

## API Endpoints

### Authentication Routes (`/api/auth`)
- `POST /signup` - Register a new user
- `POST /login` - Authenticate user and get access token
- `POST /refresh` - Refresh access token using refresh token
- `POST /logout` - Logout from current device
- `POST /logout-all` - Logout from all devices
- `GET /algorithms` - Get available JWT algorithms

### User Routes (`/api/user`)
- `GET /secret` - Get protected secret message (requires authentication)

## Usage

### Login with Optional Refresh Token
```json
POST /api/auth/login
{
  "username": "john_doe",
  "password": "securePassword123",
  "algorithm": "HS256",
  "expiresIn": "1h",
  "issueRefreshToken": true
}
```

**Note:** Set `issueRefreshToken: true` in the login request to receive a refresh token. If not specified or set to `false`, only an access token will be issued.

## Setup

- nvm install 23
- nvm use 23
- npm install
- npm run dev

### TODO

- [x] HMAC
- [x] Utils Segregation
- [x] RSA
- [x] API Expose
  - [x] Database for storing users' credentials and secret message for testing purposes
  - [x] Secret message route
- [x] Refresh Token Functionality
  - [x] Optional refresh token issuance based on user preference
- [ ] Frontend Setup
- [ ] Frontend Integration
