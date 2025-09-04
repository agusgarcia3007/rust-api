use axum::{
    middleware,
    routing::{get, post},
    Router,
};

use crate::{
    auth::auth_middleware,
    handlers::{get_profile, health_check, login, logout, logout_all, refresh_token, register},
    middleware::rate_limit::rate_limit_middleware,
    state::AppState,
};

pub fn create_routes(app_state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
        .route("/logout", post(logout))
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
        .with_state(app_state)
}
