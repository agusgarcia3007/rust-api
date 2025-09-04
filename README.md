# Rust API with Authentication

A modern Rust API built with Axum (Hono alternative) and SeaORM (Drizzle alternative) featuring JWT authentication.

## Features

- **Axum** - Fast, ergonomic web framework
- **SeaORM** - Modern async ORM with great developer experience
- **JWT Authentication** - Secure token-based authentication
- **PostgreSQL** - Production-ready database
- **bcrypt** - Secure password hashing
- **Input Validation** - Request validation with custom error messages
- **CORS** - Cross-origin resource sharing support
- **Logging** - Structured logging with tracing

## Setup

1. Install dependencies:

```bash
cargo build
```

2. Set up your environment variables in `.env`:

```bash
DATABASE_URL=your_postgresql_connection_string
JWT_SECRET=your-super-secret-jwt-key
PORT=4444
RUST_LOG=debug
```

3. Run the server:

```bash
cargo run
```

The server will start on `http://localhost:4444`

## API Endpoints

### Health Check

#### Get server status

```bash
GET /
```

Returns:

```json
{
  "status": "healthy",
  "timestamp": "2023-12-01T12:00:00.000Z",
  "service": "rust-api",
  "version": "0.1.0"
}
```

### Authentication

#### Register a new user

```bash
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "name": "John Doe"
}
```

#### Login

```bash
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

Both endpoints return:

```json
{
  "token": "jwt_token_here",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "created_at": "2023-12-01T00:00:00Z"
  }
}
```

### Protected Routes

#### Get user profile

```bash
GET /user/profile
Authorization: Bearer your_jwt_token
```

Returns:

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "name": "John Doe",
  "created_at": "2023-12-01T00:00:00Z"
}
```

## Project Structure

```
src/
├── main.rs              # Application entry point
├── config.rs            # Configuration management
├── database.rs          # Database connection
├── migration/           # Database migrations
├── entities/            # SeaORM entity models
├── dto/                 # Data transfer objects
├── auth/                # Authentication utilities and middleware
├── handlers/            # Route handlers
└── routes/              # Route definitions
```

## Development

The API automatically runs database migrations on startup. The user table will be created automatically when you first run the application.

### Testing with curl

Register a user:

```bash
curl -X POST http://localhost:4444/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","name":"Test User"}'
```

Login:

```bash
curl -X POST http://localhost:4444/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

Access protected route:

```bash
curl -X GET http://localhost:4444/user/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```
