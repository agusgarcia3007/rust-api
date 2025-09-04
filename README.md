# 🦀 Secure Rust API

A production-ready Rust API built with **Axum** and **SeaORM** featuring enterprise-grade security, JWT authentication, and comprehensive session management.

## ✨ Features

### 🔧 Core Technologies

- **Axum** - High-performance, ergonomic web framework
- **SeaORM** - Modern async ORM with excellent developer experience
- **PostgreSQL** - Production-ready relational database
- **Tokio** - Asynchronous runtime for high concurrency

### 🔒 Security Features

- **🛡️ Secure JWT Authentication** - Short-lived access tokens (15 min) with refresh token rotation
- **⚫ Token Blacklisting** - Immediate token revocation and blacklist checking
- **📱 Session Management** - Complete session tracking across devices
- **🚦 Rate Limiting** - Brute force protection on authentication endpoints
- **🔐 bcrypt Password Hashing** - Industry-standard password security
- **🧹 Automatic Cleanup** - Background task removes expired tokens/sessions

### 🚀 Developer Experience

- **✅ Input Validation** - Comprehensive request validation with detailed error messages
- **🌐 CORS Support** - Configurable cross-origin resource sharing
- **📊 Structured Logging** - Production-ready logging with tracing
- **🔄 Database Migrations** - Automatic schema management
- **📖 Comprehensive Documentation** - API documentation and security guidelines

## 🚀 Quick Start

### Prerequisites

- Rust 1.70+
- PostgreSQL 12+

### 1. Clone and Install

```bash
git clone <your-repo>
cd rust-api
cargo build
```

### 2. Environment Configuration

Create a `.env` file:

```env
DATABASE_URL=postgresql://username:password@localhost:5432/your_database
JWT_SECRET=your-super-secure-jwt-secret-key-here-min-32-chars
PORT=4444
RUST_LOG=info
```

### 3. Database Setup

```bash
# The API will automatically run migrations on startup
cargo run
```

### 4. Verify Installation

```bash
curl http://localhost:4444/
# Should return: {"status":"healthy","timestamp":"...","service":"rust-api","version":"0.1.0"}
```

## 📚 API Documentation

### 🏥 Health Check

**GET** `/`

```bash
curl http://localhost:4444/
```

```json
{
  "status": "healthy",
  "timestamp": "2024-12-01T12:00:00.000Z",
  "service": "rust-api",
  "version": "0.1.0"
}
```

### 🔐 Authentication Endpoints

All authentication endpoints are **rate limited** (5 requests per 5 minutes per IP).

#### Register User

**POST** `/auth/register`

```bash
curl -X POST http://localhost:4444/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePassword123",
    "name": "John Doe"
  }'
```

#### Login

**POST** `/auth/login`

```bash
curl -X POST http://localhost:4444/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePassword123"
  }'
```

**Response** (Register & Login):

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "John Doe",
    "created_at": "2024-12-01T00:00:00Z"
  }
}
```

#### Refresh Token

**POST** `/auth/refresh`

```bash
curl -X POST http://localhost:4444/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token_here"
  }'
```

**Response**:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### Logout (Single Session)

**POST** `/auth/logout`

```bash
curl -X POST http://localhost:4444/auth/logout \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token_here"
  }'
```

### 🔒 Protected Endpoints

All protected endpoints require the `Authorization: Bearer <access_token>` header.

#### Get User Profile

**GET** `/user/profile`

```bash
curl -X GET http://localhost:4444/user/profile \
  -H "Authorization: Bearer your_access_token_here"
```

**Response**:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "name": "John Doe",
  "created_at": "2024-12-01T00:00:00Z"
}
```

#### Logout All Devices

**POST** `/user/logout-all`

```bash
curl -X POST http://localhost:4444/user/logout-all \
  -H "Authorization: Bearer your_access_token_here"
```

**Response**:

```json
{
  "message": "Successfully logged out from all devices"
}
```

## 🏗️ Project Structure

```
src/
├── main.rs                 # Application entry point & server setup
├── config.rs              # Environment configuration management
├── database.rs            # Database connection & setup
├── state.rs               # Application state management
├── auth/                  # Authentication & security
│   ├── mod.rs
│   ├── jwt.rs             # JWT creation, validation & refresh logic
│   └── middleware.rs      # Authentication middleware & token verification
├── dto/                   # Data Transfer Objects
│   ├── mod.rs
│   └── auth.rs            # Authentication request/response DTOs
├── entities/              # Database entity models (SeaORM)
│   ├── mod.rs
│   ├── user.rs            # User entity
│   ├── session.rs         # User session tracking
│   └── token_blacklist.rs # Revoked token tracking
├── handlers/              # HTTP request handlers
│   ├── mod.rs
│   ├── auth.rs            # Authentication endpoints
│   ├── health.rs          # Health check endpoint
│   └── user.rs            # User management endpoints
├── middleware/            # Custom middleware
│   ├── mod.rs
│   └── rate_limit.rs      # Rate limiting middleware
├── migration/             # Database migrations
│   ├── mod.rs
│   ├── m20231201_000001_create_users_table.rs
│   ├── m20241201_000001_create_token_blacklist.rs
│   └── m20241201_000002_create_user_session.rs
├── routes/                # Route definitions & middleware setup
│   └── mod.rs
└── services/              # Business logic services
    ├── mod.rs
    └── token_service.rs   # Token management & session operations
```

## 🔒 Security Features

### Token Management

- **Access Tokens**: 15-minute expiration for security
- **Refresh Tokens**: 30-day expiration with secure rotation
- **Token Blacklisting**: Immediate revocation capability
- **JTI Tracking**: Unique identifier for each token

### Session Security

- **Multi-device Support**: Track sessions across devices
- **Session Metadata**: IP address and user agent logging
- **Logout Options**: Single session or all devices
- **Automatic Cleanup**: Expired sessions removed hourly

### Rate Limiting

- **Authentication Protection**: 5 requests per 5 minutes per IP
- **Memory-based Storage**: Lightweight, fast rate limiting
- **Configurable Limits**: Easy to adjust for different environments

### Password Security

- **bcrypt Hashing**: Industry-standard password hashing
- **Configurable Cost**: Different costs for development/production
- **Salt Generation**: Automatic unique salt per password

## 🔧 Development

### Running in Development

```bash
# With hot reload (install cargo-watch)
cargo install cargo-watch
cargo watch -x run

# Or standard run
cargo run
```

### Database Migrations

```bash
# Migrations run automatically on startup, or manually:
cargo run -- migrate
```

### Testing

```bash
# Run tests
cargo test

# With coverage (install cargo-tarpaulin)
cargo tarpaulin --out html
```

### Environment Configurations

#### Development (.env)

```env
DATABASE_URL=postgresql://localhost/rust_api_dev
JWT_SECRET=dev-secret-key-at-least-32-characters-long
PORT=4444
RUST_LOG=debug
```

#### Production

```env
DATABASE_URL=postgresql://prod-host/rust_api_prod
JWT_SECRET=super-secure-production-secret-key
PORT=8080
RUST_LOG=info
```

## 🔍 API Testing Examples

### Complete Authentication Flow

```bash
# 1. Register
REGISTER_RESPONSE=$(curl -s -X POST http://localhost:4444/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","name":"Test User"}')

# 2. Extract tokens
ACCESS_TOKEN=$(echo $REGISTER_RESPONSE | jq -r '.access_token')
REFRESH_TOKEN=$(echo $REGISTER_RESPONSE | jq -r '.refresh_token')

# 3. Access protected route
curl -X GET http://localhost:4444/user/profile \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# 4. Refresh token
curl -X POST http://localhost:4444/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"

# 5. Logout
curl -X POST http://localhost:4444/auth/logout \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH_TOKEN\"}"
```

## 📊 Monitoring & Observability

### Logging

The API uses structured logging with different levels:

- **ERROR**: Critical errors requiring immediate attention
- **WARN**: Warning conditions
- **INFO**: General operational messages
- **DEBUG**: Detailed information for debugging

### Health Monitoring

- Health check endpoint at `/`
- Database connection validation
- Background task status logging

## 🚀 Deployment

### Docker (Recommended)

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/rust-api /usr/local/bin/rust-api
EXPOSE 8080
CMD ["rust-api"]
```

### Environment Variables for Production

```env
DATABASE_URL=postgresql://user:pass@db:5432/production_db
JWT_SECRET=production-secret-key-minimum-32-characters
PORT=8080
RUST_LOG=info
```

## 🛡️ Security Considerations

1. **HTTPS Only**: Always use HTTPS in production
2. **Secret Management**: Use proper secret management for `JWT_SECRET`
3. **Database Security**: Use connection pooling and prepared statements
4. **Rate Limiting**: Monitor and adjust rate limits based on usage
5. **Token Storage**: Store tokens securely (httpOnly cookies recommended)
6. **Monitoring**: Set up alerts for authentication failures and rate limit hits

## 📈 Performance

- **Async/Await**: Full async support with Tokio
- **Connection Pooling**: Efficient database connection management
- **Memory Management**: Zero-copy operations where possible
- **Rate Limiting**: In-memory rate limiting for fast response times

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📚 Additional Resources

- [Security Documentation](SECURITY.md) - Detailed security features and best practices
- [Axum Documentation](https://docs.rs/axum)
- [SeaORM Documentation](https://docs.rs/sea-orm)
- [JWT Best Practices](https://tools.ietf.org/html/rfc7519)

---

**Built with ❤️ in Rust** 🦀
