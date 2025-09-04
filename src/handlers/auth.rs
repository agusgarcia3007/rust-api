use axum::{extract::State, http::StatusCode, response::Json, Extension};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use validator::Validate;

use crate::{
    auth::{hash_password, verify_password},
    dto::{AuthResponse, LoginRequest, RefreshTokenRequest, RefreshTokenResponse, RegisterRequest, UserResponse, ConfirmEmailRequest, ForgotPasswordRequest, ResetPasswordRequest, MessageResponse},
    entities::{user, User},
    services::{token_service::TokenService, email_service::EmailService},
    state::AppState,
};
use rand::Rng;
use chrono::{Duration, Utc};

#[utoipa::path(
    post,
    path = "/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = AuthResponse),
        (status = 400, description = "Validation failed"),
        (status = 409, description = "User already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authentication"
)]
pub async fn register(
    State(app_state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(errors) = payload.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Validation failed",
                "details": errors
            })),
        ));
    }

    let existing_user = User::find()
        .filter(user::Column::Email.eq(&payload.email))
        .one(&app_state.db)
        .await
        .map_err(|err| {
            tracing::error!("Database error checking existing user: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
        })?;

    if existing_user.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "User already exists"})),
        ));
    }

    let password_hash = hash_password(&payload.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to hash password"})),
        )
    })?;

    let verification_token = generate_verification_token();
    let expires_at = Utc::now() + Duration::hours(24);

    let new_user = user::ActiveModel {
        email: Set(payload.email.clone()),
        password_hash: Set(password_hash),
        name: Set(payload.name.clone()),
        email_verification_token: Set(Some(verification_token.clone())),
        email_verification_expires_at: Set(Some(expires_at)),
        ..Default::default()
    };

    let user = new_user.insert(&app_state.db).await.map_err(|err| {
        tracing::error!("Database error creating user: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to create user"})),
        )
    })?;

    let email_service = EmailService::new().map_err(|_| {
        tracing::error!("Failed to initialize email service");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Email service unavailable"})),
        )
    })?;

    let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    
    if let Err(e) = email_service.send_signup_confirmation(
        &payload.email,
        &payload.name,
        &verification_token,
        &base_url,
    ).await {
        tracing::error!("Failed to send confirmation email: {:?}", e);
    }

    let (access_token, refresh_token_jwt) = TokenService::create_session(
        &app_state.db,
        &user,
        &app_state.config.jwt_secret,
        None,
        None,
    ).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to create session"})),
        )
    })?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: refresh_token_jwt,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        user: UserResponse {
            id: user.id,
            email: user.email,
            name: user.name,
            created_at: user.created_at,
        },
    }))
}

#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 400, description = "Validation failed"),
        (status = 401, description = "Invalid credentials"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authentication"
)]
pub async fn login(
    State(app_state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(errors) = payload.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Validation failed",
                "details": errors
            })),
        ));
    }

    let user = User::find()
        .filter(user::Column::Email.eq(&payload.email))
        .one(&app_state.db)
        .await
        .map_err(|err| {
            tracing::error!("Database error finding user: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
        })?;

    let user = match user {
        Some(user) => user,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid credentials"})),
            ))
        }
    };

    let is_valid = verify_password(&payload.password, &user.password_hash).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to verify password"})),
        )
    })?;

    if !is_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid credentials"})),
        ));
    }

    let (access_token, refresh_token_jwt) = TokenService::create_session(
        &app_state.db,
        &user,
        &app_state.config.jwt_secret,
        None,
        None,
    ).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to create session"})),
        )
    })?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: refresh_token_jwt,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        user: UserResponse {
            id: user.id,
            email: user.email,
            name: user.name,
            created_at: user.created_at,
        },
    }))
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Token refreshed successfully", body = RefreshTokenResponse),
        (status = 401, description = "Invalid refresh token"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authentication"
)]
pub async fn refresh_token(
    State(app_state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let new_access_token = TokenService::refresh_access_token(
        &app_state.db,
        &payload.refresh_token,
        &app_state.config.jwt_secret,
    ).await.map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid refresh token"})),
        )
    })?;

    Ok(Json(RefreshTokenResponse {
        access_token: new_access_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
    }))
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Logout successful"),
        (status = 401, description = "Invalid refresh token"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authentication"
)]
pub async fn logout(
    State(app_state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let refresh_claims = crate::auth::verify_refresh_token(&payload.refresh_token, &app_state.config.jwt_secret)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid refresh token"})),
            )
        })?;

    let user_id = uuid::Uuid::parse_str(&refresh_claims.sub).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid user ID"})),
        )
    })?;

    TokenService::logout_session(&app_state.db, &payload.refresh_token, user_id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to logout"})),
            )
        })?;

    Ok(Json(serde_json::json!({"message": "Successfully logged out"})))
}

#[utoipa::path(
    post,
    path = "/user/logout-all",
    responses(
        (status = 200, description = "Logout from all devices successful"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "User"
)]
pub async fn logout_all(
    State(app_state): State<AppState>,
    Extension(user): Extension<user::Model>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    TokenService::revoke_all_user_sessions(&app_state.db, user.id, Some("logout_all".to_string()))
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to logout from all devices"})),
            )
        })?;

    Ok(Json(serde_json::json!({"message": "Successfully logged out from all devices"})))
}

fn generate_verification_token() -> String {
    let mut rng = rand::thread_rng();
    let token: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            match idx {
                0..=25 => (b'a' + idx) as char,
                26..=51 => (b'A' + idx - 26) as char,
                _ => (b'0' + idx - 52) as char,
            }
        })
        .collect();
    token
}

#[utoipa::path(
    post,
    path = "/auth/confirm-email",
    request_body = ConfirmEmailRequest,
    responses(
        (status = 200, description = "Email confirmed successfully", body = MessageResponse),
        (status = 400, description = "Invalid or expired token"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authentication"
)]
pub async fn confirm_email(
    State(app_state): State<AppState>,
    Json(payload): Json<ConfirmEmailRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    let user = User::find()
        .filter(user::Column::EmailVerificationToken.eq(&payload.token))
        .one(&app_state.db)
        .await
        .map_err(|err| {
            tracing::error!("Database error finding user: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
        })?;

    let user = match user {
        Some(user) => user,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid verification token"})),
            ))
        }
    };

    if let Some(expires_at) = user.email_verification_expires_at {
        if Utc::now() > expires_at {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Verification token has expired"})),
            ));
        }
    }

    let mut user_active: user::ActiveModel = user.into();
    user_active.email_verified = Set(true);
    user_active.email_verification_token = Set(None);
    user_active.email_verification_expires_at = Set(None);
    user_active.updated_at = Set(Utc::now());

    user_active.update(&app_state.db).await.map_err(|err| {
        tracing::error!("Database error updating user: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to confirm email"})),
        )
    })?;

    Ok(Json(MessageResponse {
        message: "Email confirmed successfully".to_string(),
    }))
}

#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, description = "Password reset email sent", body = MessageResponse),
        (status = 400, description = "Validation failed"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authentication"
)]
pub async fn forgot_password(
    State(app_state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(errors) = payload.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Validation failed",
                "details": errors
            })),
        ));
    }

    let user = User::find()
        .filter(user::Column::Email.eq(&payload.email))
        .one(&app_state.db)
        .await
        .map_err(|err| {
            tracing::error!("Database error finding user: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
        })?;

    let user = match user {
        Some(user) => user,
        None => {
            return Ok(Json(MessageResponse {
                message: "If an account with that email exists, a password reset link has been sent".to_string(),
            }))
        }
    };

    let reset_token = generate_verification_token();
    let expires_at = Utc::now() + Duration::hours(1);

    let mut user_active: user::ActiveModel = user.clone().into();
    user_active.password_reset_token = Set(Some(reset_token.clone()));
    user_active.password_reset_expires_at = Set(Some(expires_at));
    user_active.updated_at = Set(Utc::now());

    user_active.update(&app_state.db).await.map_err(|err| {
        tracing::error!("Database error updating user: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Database error"})),
        )
    })?;

    let email_service = EmailService::new().map_err(|_| {
        tracing::error!("Failed to initialize email service");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Email service unavailable"})),
        )
    })?;

    let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    
    if let Err(e) = email_service.send_password_reset(
        &user.email,
        &user.name,
        &reset_token,
        &base_url,
    ).await {
        tracing::error!("Failed to send password reset email: {:?}", e);
    }

    Ok(Json(MessageResponse {
        message: "If an account with that email exists, a password reset link has been sent".to_string(),
    }))
}

#[utoipa::path(
    post,
    path = "/auth/reset-password",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset successfully", body = MessageResponse),
        (status = 400, description = "Invalid or expired token"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authentication"
)]
pub async fn reset_password(
    State(app_state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(errors) = payload.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Validation failed",
                "details": errors
            })),
        ));
    }

    let user = User::find()
        .filter(user::Column::PasswordResetToken.eq(&payload.token))
        .one(&app_state.db)
        .await
        .map_err(|err| {
            tracing::error!("Database error finding user: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
        })?;

    let user = match user {
        Some(user) => user,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid reset token"})),
            ))
        }
    };

    if let Some(expires_at) = user.password_reset_expires_at {
        if Utc::now() > expires_at {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Reset token has expired"})),
            ));
        }
    }

    let password_hash = hash_password(&payload.new_password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to hash password"})),
        )
    })?;

    let mut user_active: user::ActiveModel = user.into();
    user_active.password_hash = Set(password_hash);
    user_active.password_reset_token = Set(None);
    user_active.password_reset_expires_at = Set(None);
    user_active.updated_at = Set(Utc::now());

    user_active.update(&app_state.db).await.map_err(|err| {
        tracing::error!("Database error updating user: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to reset password"})),
        )
    })?;

    Ok(Json(MessageResponse {
        message: "Password reset successfully".to_string(),
    }))
}