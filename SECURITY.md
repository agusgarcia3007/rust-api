# Security Features

This API implements comprehensive security measures to protect against common vulnerabilities and ensure secure token management.

## Authentication & Authorization

### JWT Token Security

- **Short-lived Access Tokens**: Access tokens expire in 15 minutes
- **Refresh Token Rotation**: Secure refresh tokens with 30-day expiration
- **Token Blacklisting**: Revoked tokens are blacklisted and checked on every request
- **JTI (JWT ID)**: Each token has a unique identifier for tracking and revocation
- **Strong Algorithm**: Uses HS256 with proper validation
- **Token Type Validation**: Distinguishes between access and refresh tokens

### Session Management

- **Session Tracking**: All user sessions are tracked in the database
- **Device Management**: Support for logging out from all devices
- **Session Metadata**: IP address and user agent tracking
- **Automatic Cleanup**: Expired sessions and blacklisted tokens are cleaned up

### Rate Limiting

- **Authentication Endpoints**: Limited to 5 requests per 5 minutes per IP
- **Brute Force Protection**: Prevents password guessing attacks
- **Memory-based Storage**: Lightweight in-memory rate limiting

## API Endpoints

### Authentication

- `POST /auth/register` - User registration (rate limited)
- `POST /auth/login` - User login (rate limited)
- `POST /auth/refresh` - Refresh access token (rate limited)
- `POST /auth/logout` - Logout single session (rate limited)

### Protected Endpoints

- `GET /user/profile` - Get user profile (requires auth)
- `POST /user/logout-all` - Logout from all devices (requires auth)

## Security Headers & Middleware

### CORS Configuration

- Configurable allowed origins
- Secure headers (Authorization, Content-Type, Accept)
- Proper preflight handling

### Authentication Middleware

- Bearer token validation
- Token blacklist checking
- User existence verification
- Request context injection

## Database Security

### Password Security

- **bcrypt Hashing**: Strong password hashing with configurable cost
- **Development vs Production**: Lower cost in debug mode for faster testing
- **Salt Generation**: Automatic salt generation per password

### Token Storage

- **Encrypted JTI**: Unique identifiers for each token
- **Expiration Tracking**: Database-level expiration management
- **Cascade Deletion**: Automatic cleanup on user deletion

## Environment Variables

Required environment variables:

```env
DATABASE_URL=postgresql://user:password@localhost/dbname
JWT_SECRET=your-super-secret-jwt-key-here
PORT=4444
```

## Security Best Practices Implemented

1. **No Token Storage in Client**: Tokens should be stored securely (httpOnly cookies recommended)
2. **Token Rotation**: Regular refresh token rotation prevents long-term compromise
3. **Blacklist Management**: Immediate token revocation capability
4. **Rate Limiting**: Protection against brute force attacks
5. **Strong Validation**: Comprehensive JWT claim validation
6. **Session Tracking**: Full audit trail of user sessions
7. **Secure Defaults**: Production-ready security configurations

## Migration Required

To use the secure authentication system, run the database migrations:

```bash
cargo run -- migrate
```

This will create the required tables:

- `token_blacklist` - For tracking revoked tokens
- `user_session` - For managing user sessions

## Usage Examples

### Login Flow

```bash
# Login
curl -X POST http://localhost:4444/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Response includes both access_token and refresh_token
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {...}
}
```

### Using Access Token

```bash
curl -X GET http://localhost:4444/user/profile \
  -H "Authorization: Bearer eyJ..."
```

### Refreshing Token

```bash
curl -X POST http://localhost:4444/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJ..."}'
```

### Logout

```bash
# Logout single session
curl -X POST http://localhost:4444/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJ..."}'

# Logout all sessions
curl -X POST http://localhost:4444/user/logout-all \
  -H "Authorization: Bearer eyJ..."
```

## Security Considerations

1. **HTTPS Only**: Always use HTTPS in production
2. **Secure Storage**: Store tokens in httpOnly cookies, not localStorage
3. **Token Rotation**: Implement automatic token refresh in your client
4. **Monitoring**: Monitor for unusual authentication patterns
5. **Cleanup**: Regularly run token cleanup operations
6. **Secrets Management**: Use proper secret management for JWT_SECRET
