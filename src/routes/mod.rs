use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    auth::auth_middleware,
    dto::{AuthResponse, LoginRequest, RefreshTokenRequest, RefreshTokenResponse, RegisterRequest, UserResponse, ConfirmEmailRequest, ForgotPasswordRequest, ResetPasswordRequest, MessageResponse},
    handlers::{get_profile, health_check, login, logout, logout_all, refresh_token, register, confirm_email, forgot_password, reset_password,
        __path_get_profile, __path_health_check, __path_login, __path_logout, __path_logout_all, __path_refresh_token, __path_register, __path_confirm_email, __path_forgot_password, __path_reset_password},
    middleware::rate_limit::rate_limit_middleware,
    state::AppState,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        health_check,
        register,
        login,
        refresh_token,
        logout,
        get_profile,
        logout_all,
        confirm_email,
        forgot_password,
        reset_password
    ),
    components(
        schemas(RegisterRequest, LoginRequest, RefreshTokenRequest, AuthResponse, RefreshTokenResponse, UserResponse, ConfirmEmailRequest, ForgotPasswordRequest, ResetPasswordRequest, MessageResponse)
    ),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Authentication", description = "Authentication endpoints"),
        (name = "User", description = "User management endpoints")
    ),
    info(
        title = "Rust Auth API",
        version = "0.1.0",
        description = "A REST API for user authentication and management built with Rust and Axum"
    ),
    servers(
        (url = "http://localhost:4444", description = "Development server")
    )
)]
pub struct ApiDoc;

pub fn create_routes(app_state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
        .route("/logout", post(logout))
        .route("/confirm-email", post(confirm_email))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
        .route_layer(middleware::from_fn(rate_limit_middleware));

    let protected_routes = Router::new()
        .route("/profile", get(get_profile))
        .route("/logout-all", post(logout_all))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    Router::new()
        .route("/", get(health_check))
        .nest("/auth", auth_routes)
        .nest("/user", protected_routes)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(app_state)
}
